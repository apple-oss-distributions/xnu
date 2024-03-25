/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#if CONFIG_EXCLAVES

#include <stdint.h>

#include <mach/exclaves.h>
#include <mach/kern_return.h>

#include <string.h>

#include <kern/assert.h>
#include <kern/queue.h>
#include <kern/kalloc.h>
#include <kern/locks.h>
#include <kern/task.h>
#include <kern/thread_call.h>

#include <vm/pmap.h>


#include <kern/ipc_kobject.h>

#include <os/hash.h>

#include <libxnuproxy/messages.h>

#include <mach/mach_traps.h>
#include <mach/mach_port.h>

#include <sys/event.h>

#include "exclaves_resource.h"
#include "exclaves_shared_memory.h"
#include "exclaves_sensor.h"
#include "exclaves_conclave.h"

/* Use the new version of xnuproxy_msg_t. */
#define xnuproxy_msg_t xnuproxy_msg_new_t

static LCK_GRP_DECLARE(resource_lck_grp, "exclaves_resource");

extern kern_return_t exclaves_xnu_proxy_send(xnuproxy_msg_t *, void *);

/*
 * Exclave Resources
 *
 * Exclaves provide a fixed static set of resources available to XNU. Some
 * examples of types of resources:
 *     - Conclave managers
 *     - Services
 *     - Named buffers
 *     - Audio buffers
 *     ...
 *
 * Each resource has a name, a type and a corresponding identifier which is
 * shared between XNU and Exclaves. Resources are scoped by what entities are
 * allowed to access them.
 * Resources are discovered during boot and made available in a two-level table
 * scheme. The root table collects resources by their scope, with the
 * second-level tables listing the actual resources.
 *
 *
 *           Root Table
 * ┌────────────────────────────┐
 * │ ┌────────────────────────┐ │
 * │ │  "com.apple.kernel"    │─┼─────┐
 * │ └────────────────────────┘ │     │
 * │ ┌────────────────────────┐ │     │
 * │ │"com.apple.conclave.a"  │─┼─┐   │
 * │ └────────────────────────┘ │ │   │
 * │ ┌────────────────────────┐ │ │   │
 * │ │"com.apple.conclave.b"  │ │ │   │
 * │ └────────────────────────┘ │ │   │
 * │ ┌────────────────────────┐ │ │   │
 * │ │ "com.apple.driver.a"   │ │ │   │
 * │ └────────────────────────┘ │ │   │
 * │  ...                       │ │   │
 * │                            │ │   │
 * └────────────────────────────┘ │   │
 *      ┌─────────────────────────┘   │
 *      │                             │
 *      │   ┌─────────────────────────┘
 *      │   │
 *      │   │
 *      │   │
 *      │   └──▶  "com.apple.kernel"
 *      │        ┌─────────────────────────────────────────────────────┐
 *      │        │┌───────────────────────┬──────────────────┬────────┐│
 *      │        ││"com.apple.conclave.a" │ CONCLAVE_MANAGER │ 0x1234 ││
 *      │        │└───────────────────────┴──────────────────┴────────┘│
 *      │        │┌───────────────────────┬──────────────────┬────────┐│
 *      │        ││"com.apple.conclave.b" │ CONCLAVE_MANAGER │ 0x7654 ││
 *      │        │└───────────────────────┴──────────────────┴────────┘│
 *      │        │                                                     │
 *      │        │  ...                                                │
 *      │        └─────────────────────────────────────────────────────┘
 *      │
 *      └─────▶   "com.apple.conclave.a"
 *               ┌─────────────────────────────────────────────────────┐
 *               │┌───────────────────────┬──────────────────┬────────┐│
 *               ││      "audio_buf"      │   AUDIO_BUFFER   │ 0x9999 ││
 *               │└───────────────────────┴──────────────────┴────────┘│
 *               │┌───────────────────────┬──────────────────┬────────┐│
 *               ││      "service_x"      │     SERVICE      │ 0x1111 ││
 *               │└───────────────────────┴──────────────────┴────────┘│
 *               │┌───────────────────────┬──────────────────┬────────┐│
 *               ││   "named_buffer_x"    │   NAMED_BUFFER   │0x66565 ││
 *               │└───────────────────────┴──────────────────┴────────┘│
 *               │  ...                                                │
 *               └─────────────────────────────────────────────────────┘
 *
 *                 ...
 *
 *
 * Resources can be looked up by first finding the root table entry (the
 * "domain") and then searching for the identifier in that domain.
 * For example to lookup the conclave manager ID for "com.apple.conclave.a",
 * the "com.apple.kernel" domain would be found and then within that domain, the
 * search would continue using the conclave name and the CONCLAVE_MANAGER type.
 * Every conclave domain has a corresponding CONCLAVE_MANAGER resource in the
 * "com.apple.kernel" domain.
 */

/* -------------------------------------------------------------------------- */
#pragma mark Hash Table

#define TABLE_LEN 64

/*
 * A table item is what ends up being stored in the hash table. It has a key and
 * a value.
 */
typedef struct {
	const void    *i_key;
	size_t         i_key_len;
	void          *i_value;

	queue_chain_t  i_chain;
} table_item_t;

/*
 * The hash table consists of an array of buckets (queues). The hashing function
 * will choose in which bucket a particular item belongs.
 */
typedef struct {
	queue_head_t *t_buckets;
	size_t        t_buckets_count;
} table_t;

/*
 * Given a key, return the corresponding bucket.
 */
static queue_head_t *
get_bucket(table_t *table, const void *key, size_t key_len)
{
	const uint32_t idx = os_hash_jenkins(key, key_len) &
	    (table->t_buckets_count - 1);
	return &table->t_buckets[idx];
}

/*
 * Insert a new table item associated with 'key' into a table.
 */
static void
table_put(table_t *table, const void *key, size_t key_len, table_item_t *item)
{
	assert3p(item->i_chain.next, ==, NULL);
	assert3p(item->i_chain.prev, ==, NULL);
	assert3p(item->i_value, !=, NULL);

	queue_head_t *head = get_bucket(table, key, key_len);
	enqueue(head, &item->i_chain);
}

/*
 * Iterate through all items matching 'key' calling cb for each.
 */
static void
table_get(table_t *table, const void *key, size_t key_len, bool (^cb)(void *))
{
	const queue_head_t *head = get_bucket(table, key, key_len);
	table_item_t *elem = NULL;

	assert3p(head, !=, NULL);

	qe_foreach_element(elem, head, i_chain) {
		if (elem->i_key_len == key_len &&
		    memcmp(elem->i_key, key, elem->i_key_len) == 0) {
			if (cb(elem->i_value)) {
				return;
			}
		}
	}

	return;
}

/*
 * Initialize the queues.
 */
static void
table_init(table_t *table)
{
	assert3u(table->t_buckets_count & (table->t_buckets_count - 1), ==, 0);

	/* Initialise each bucket. */
	for (size_t i = 0; i < table->t_buckets_count; i++) {
		queue_init(&table->t_buckets[i]);
	}
}

/*
 * Allocate a new table with the specified number of buckets.
 */
static table_t *
table_alloc(size_t nbuckets)
{
	assert3u(nbuckets, >, 0);
	assert3u(nbuckets & (nbuckets - 1), ==, 0);

	table_t *table = kalloc_type(table_t, Z_WAITOK | Z_ZERO | Z_NOFAIL);

	table->t_buckets_count = nbuckets;
	table->t_buckets = kalloc_type(queue_head_t, nbuckets,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);

	return table;
}


/* -------------------------------------------------------------------------- */
#pragma mark Root Table

/*
 * The root table is a hash table which contains an entry for every top-level
 * domain.
 * Domains scope resources. For example a conclave domain will contain a list of
 * services available in that conclave. The kernel itself gets its own domain
 * which holds conclave managers and other resources the kernel communicates
 * with directly.
 */
table_t root_table = {
	.t_buckets = (queue_chain_t *)(queue_chain_t[TABLE_LEN]){},
	.t_buckets_count = TABLE_LEN,
};

/*
 * Entries in the root table. Each itself a table containing resources available
 * in that domain.
 */
typedef struct {
	char     d_name[XNUPROXY_RESOURCE_NAME_MAX];
	table_t *d_table_name;
	table_t *d_table_id;
} exclaves_resource_domain_t;

static exclaves_resource_domain_t *
lookup_domain(const char *domain_name)
{
	__block exclaves_resource_domain_t *domain = NULL;
	table_get(&root_table, domain_name, strlen(domain_name), ^bool (void *data) {
		domain = data;
		return true;
	});

	return domain;
}

static exclaves_resource_t *
lookup_resource_by_name(exclaves_resource_domain_t *domain, const char *name,
    xnuproxy_resource_t type)
{
	__block exclaves_resource_t *resource = NULL;
	table_get(domain->d_table_name, name, strlen(name), ^bool (void *data) {
		exclaves_resource_t *tmp = data;
		if (tmp->r_type == type) {
		        resource = data;
		        return true;
		}
		return false;
	});

	return resource;
}

static exclaves_resource_t *
lookup_resource_by_id(exclaves_resource_domain_t *domain, uint64_t id,
    xnuproxy_resource_t type)
{
	__block exclaves_resource_t *resource = NULL;
	table_get(domain->d_table_id, &id, sizeof(id), ^bool (void *data) {
		exclaves_resource_t *tmp = data;
		if (tmp->r_type == type) {
		        resource = data;
		        return true;
		}
		return false;
	});

	return resource;
}

static exclaves_resource_domain_t *
exclaves_resource_domain_alloc(const char *scope)
{
	assert3u(strlen(scope), >, 0);
	assert3u(strlen(scope), <=, XNUPROXY_RESOURCE_NAME_MAX);

	exclaves_resource_domain_t *domain = kalloc_type(
		exclaves_resource_domain_t, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	(void) strlcpy(domain->d_name, scope,
	    sizeof(domain->d_name));

	domain->d_table_name = table_alloc(TABLE_LEN);
	table_init(domain->d_table_name);

	domain->d_table_id = table_alloc(TABLE_LEN);
	table_init(domain->d_table_id);

	table_item_t *item = kalloc_type(table_item_t,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);
	item->i_key = domain->d_name;
	item->i_key_len = strlen(domain->d_name);
	item->i_value = domain;

	table_put(&root_table, scope, strlen(scope), item);

	return domain;
}

static exclaves_resource_t *
exclaves_resource_alloc(xnuproxy_resource_t type, const char *name, uint64_t id,
    exclaves_resource_domain_t *domain)
{
	exclaves_resource_t *resource = kalloc_type(exclaves_resource_t,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);

	resource->r_type = type;
	resource->r_id = id;
	resource->r_active = false;
	os_atomic_store(&resource->r_usecnt, 0, relaxed);

	/*
	 * Each resource has an associated kobject of type
	 * IKOT_EXCLAVES_RESOURCE.
	 */
	ipc_port_t port = ipc_kobject_alloc_port((ipc_kobject_t)resource,
	    IKOT_EXCLAVES_RESOURCE, IPC_KOBJECT_ALLOC_NSREQUEST);
	resource->r_port = port;

	lck_mtx_init(&resource->r_mutex, &resource_lck_grp, NULL);

	(void) strlcpy(resource->r_name, name, sizeof(resource->r_name));


	/* Stick the newly created resource into the name table. */
	table_item_t *name_item = kalloc_type(table_item_t,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);

	name_item->i_key = resource->r_name;
	name_item->i_key_len = strlen(resource->r_name);
	name_item->i_value = resource;

	assert(lookup_resource_by_name(domain, name, type) == NULL);
	table_put(domain->d_table_name, name, strlen(name), name_item);

	/*
	 * Some types also need to lookup by id in addition to looking up by
	 * name.
	 */
	switch (type) {
	case XNUPROXY_RESOURCE_NOTIFICATION: {
		/* Stick the newly created resource into the ID table. */
		table_item_t *id_item = kalloc_type(table_item_t,
		    Z_WAITOK | Z_ZERO | Z_NOFAIL);
		id_item->i_key = &resource->r_id;
		id_item->i_key_len = sizeof(resource->r_id);
		id_item->i_value = resource;

		assert(lookup_resource_by_id(domain, id, type) == NULL);
		table_put(domain->d_table_id, &id, sizeof(id), id_item);
		break;
	}

	default:
		break;
	}

	return resource;
}

/* -------------------------------------------------------------------------- */
#pragma mark Exclaves Resources

static void exclaves_resource_no_senders(ipc_port_t port,
    mach_port_mscount_t mscount);

IPC_KOBJECT_DEFINE(IKOT_EXCLAVES_RESOURCE,
    .iko_op_stable = true,
    .iko_op_no_senders = exclaves_resource_no_senders);

static void exclaves_conclave_init(exclaves_resource_t *resource);
static void exclaves_notification_init(exclaves_resource_t *resource);
static void exclaves_named_buffer_unmap(exclaves_resource_t *resource);
static void exclaves_audio_buffer_delete(exclaves_resource_t *resource);
static void exclaves_resource_sensor_reset(exclaves_resource_t *resource);
static void exclaves_resource_shared_memory_unmap(exclaves_resource_t *resource);
static void exclaves_resource_audio_memory_unmap(exclaves_resource_t *resource);

/*
 * Discover all the static exclaves resources populating the resource tables as
 * we go.
 */
kern_return_t
exclaves_resource_init(void)
{
	/* Initialize the root table. */
	table_init(&root_table);

	for (uint32_t i = 0;; i++) {
		/* Get info about the 'i'th resource. */
		xnuproxy_msg_t msg = {
			.cmd = XNUPROXY_CMD_RESOURCE_INFO,
			.cmd_resource_info = (xnuproxy_cmd_resource_info_t) {
				.request.index = i,
			},
		};

		kern_return_t kr = exclaves_xnu_proxy_send(&msg, NULL);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		/*
		 * An empty name indicates there are no resources left to
		 * enumerate.
		 */
		if (msg.cmd_resource_info.response.name[0] == '\0') {
			break;
		}

		xnuproxy_resource_t type = msg.cmd_resource_info.response.type;
		const char *name =
		    (const char *)&msg.cmd_resource_info.response.name;
		const uint64_t id = msg.cmd_resource_info.response.id;
		const char *scope =
		    (const char *)&msg.cmd_resource_info.response.domain;

		/*
		 * Every resource is scoped to a specific domain, find the
		 * domain (or create one if it doesn't exist).
		 */
		exclaves_resource_domain_t *domain = lookup_domain(scope);
		if (domain == NULL) {
			domain = exclaves_resource_domain_alloc(scope);
		}

		/* Allocate a new resource in the domain. */
		exclaves_resource_t *resource = exclaves_resource_alloc(type,
		    name, id, domain);

		/*
		 * Type specific initialization.
		 */
		switch (type) {
		case XNUPROXY_RESOURCE_CONCLAVE_MANAGER:
			exclaves_conclave_init(resource);
			break;

		case XNUPROXY_RESOURCE_NOTIFICATION:
			exclaves_notification_init(resource);
			break;

		default:
			break;
		}
	}

	return KERN_SUCCESS;
}

exclaves_resource_t *
exclaves_resource_lookup_by_name(const char *domain_name, const char *name,
    xnuproxy_resource_t type)
{
	assert3u(strlen(domain_name), >, 0);
	assert3u(strlen(name), >, 0);

	exclaves_resource_domain_t *domain = lookup_domain(domain_name);
	if (domain == NULL) {
		return NULL;
	}

	return lookup_resource_by_name(domain, name, type);
}

static exclaves_resource_t *
exclaves_resource_lookup_by_id(const char *domain_name, uint64_t id,
    xnuproxy_resource_t type)
{
	assert3u(strlen(domain_name), >, 0);

	exclaves_resource_domain_t *domain = lookup_domain(domain_name);
	if (domain == NULL) {
		return NULL;
	}

	return lookup_resource_by_id(domain, id, type);
}

const char *
exclaves_resource_name(const exclaves_resource_t *resource)
{
	return resource->r_name;
}

/*
 * Notes on use-count management
 * For the most part everything is done under the resource lock.
 * In some cases, it's necessary to grab/release a use count without
 * holding the lock - for example the realtime audio paths doing copyin/copyout
 * of named buffers/audio buffers.
 * To prevent against races, initialization/de-initialization should always
 * recheck the use-count under the lock.
 */
uint32_t
exclaves_resource_retain(exclaves_resource_t *resource)
{
	uint32_t orig =
	    os_atomic_inc_orig(&resource->r_usecnt, relaxed);
	assert3u(orig, <, UINT32_MAX);

	return orig;
}

void
exclaves_resource_release(exclaves_resource_t *resource)
{
	/*
	 * Drop the use count without holding the lock (this path may be called
	 * by RT threads and should be RT-safe).
	 */
	uint32_t orig = os_atomic_dec_orig(&resource->r_usecnt, relaxed);
	assert3u(orig, !=, 0);
	if (orig != 1) {
		return;
	}

	/*
	 * Now grab the lock. The RT-safe paths calling this function shouldn't
	 * end up here unless there's a bug or mis-behaving user code (like
	 * deallocating an in-use mach port).
	 */
	lck_mtx_lock(&resource->r_mutex);

	/*
	 * Re-check the use count - as a second user of the resource
	 * may have snuck in in the meantime.
	 */
	if (os_atomic_load(&resource->r_usecnt, relaxed) > 0) {
		lck_mtx_unlock(&resource->r_mutex);
		return;
	}

	switch (resource->r_type) {
	case XNUPROXY_RESOURCE_NAMED_BUFFER:
		exclaves_named_buffer_unmap(resource);
		break;

	case XNUPROXY_RESOURCE_ARBITRATED_AUDIO_BUFFER:
		exclaves_audio_buffer_delete(resource);
		break;

	case XNUPROXY_RESOURCE_SENSOR:
		exclaves_resource_sensor_reset(resource);
		break;

	case XNUPROXY_RESOURCE_SHARED_MEMORY:
		exclaves_resource_shared_memory_unmap(resource);
		break;

	case XNUPROXY_RESOURCE_ARBITRATED_AUDIO_MEMORY:
		exclaves_resource_audio_memory_unmap(resource);
		break;

	default:
		break;
	}

	lck_mtx_unlock(&resource->r_mutex);
}

kern_return_t
exclaves_resource_from_port_name(ipc_space_t space, mach_port_name_t name,
    exclaves_resource_t **out)
{
	kern_return_t kr = KERN_SUCCESS;
	ipc_port_t port = IPC_PORT_NULL;

	if (!MACH_PORT_VALID(name)) {
		return KERN_INVALID_NAME;
	}

	kr = ipc_port_translate_send(space, name, &port);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	/* port is locked */
	assert(IP_VALID(port));

	exclaves_resource_t *resource = ipc_kobject_get_stable(port,
	    IKOT_EXCLAVES_RESOURCE);

	/* The port is valid, but doesn't denote an exclaves resource. */
	if (resource == NULL) {
		ip_mq_unlock(port);
		return KERN_INVALID_CAPABILITY;
	}

	/* Grab a reference while the port is good and the ipc lock is held. */
	__assert_only uint32_t orig = exclaves_resource_retain(resource);
	assert3u(orig, >, 0);

	ip_mq_unlock(port);
	*out = resource;

	return KERN_SUCCESS;
}

/*
 * Consumes a reference to the resource. On success the resource is reference is
 * associated with the lifetime of the port.
 */
kern_return_t
exclaves_resource_create_port_name(exclaves_resource_t *resource, ipc_space_t space,
    mach_port_name_t *name)
{
	assert3u(os_atomic_load(&resource->r_usecnt, relaxed), >, 0);

	ipc_port_t port = resource->r_port;

	ip_mq_lock(port);

	/* Create an armed send right. */
	kern_return_t ret = ipc_kobject_make_send_nsrequest_locked(port,
	    resource, IKOT_EXCLAVES_RESOURCE);
	if (ret != KERN_SUCCESS &&
	    ret != KERN_ALREADY_WAITING) {
		ip_mq_unlock(port);
		exclaves_resource_release(resource);
		return ret;
	}

	/*
	 * If there was already a send right, then the port already has an
	 * associated use count so drop this one.
	 */
	if (port->ip_srights > 1) {
		assert3u(os_atomic_load(&resource->r_usecnt, relaxed), >, 1);
		exclaves_resource_release(resource);
	}

	ip_mq_unlock(port);

	*name = ipc_port_copyout_send(port, space);
	if (!MACH_PORT_VALID(*name)) {
		/*
		 * ipc_port_copyout_send() releases the send right on failure
		 * (possibly calling exclaves_resource_no_senders() in the
		 * process).
		 */
		return KERN_RESOURCE_SHORTAGE;
	}

	return KERN_SUCCESS;
}

static void
exclaves_resource_no_senders(ipc_port_t port,
    __unused mach_port_mscount_t mscount)
{
	exclaves_resource_t *resource = ipc_kobject_get_stable(port,
	    IKOT_EXCLAVES_RESOURCE);

	exclaves_resource_release(resource);
}

/* -------------------------------------------------------------------------- */
#pragma mark Named Buffers

int
exclaves_named_buffer_io(exclaves_resource_t *resource, off_t offset,
    size_t len, int (^cb)(char *, size_t))
{
	assert(resource->r_type == XNUPROXY_RESOURCE_NAMED_BUFFER ||
	    resource->r_type == XNUPROXY_RESOURCE_ARBITRATED_AUDIO_BUFFER);
	assert3u(os_atomic_load(&resource->r_usecnt, relaxed), >, 0);

	named_buffer_resource_t *nb = &resource->r_named_buffer;
	assert3u(nb->nb_nranges, >, 0);
	assert3u(nb->nb_size, !=, 0);
	assert3u(offset + len, <=, nb->nb_size);

	for (int i = 0; i < nb->nb_nranges; i++) {
		/* Skip forward to the starting range. */
		if (offset >= nb->nb_range[i].npages * PAGE_SIZE) {
			offset -= nb->nb_range[i].npages * PAGE_SIZE;
			continue;
		}

		size_t size = MIN((nb->nb_range[i].npages * PAGE_SIZE) - offset, len);
		int ret = cb(nb->nb_range[i].address + offset, size);
		if (ret != 0) {
			return ret;
		}

		offset = 0;
		len -= size;

		if (len == 0) {
			break;
		}
	}
	assert3u(len, ==, 0);

	return 0;
}

static kern_return_t
exclaves_named_buffer_io_copyin(exclaves_resource_t *resource,
    user_addr_t _src, off_t offset, size_t len)
{
	assert3u(resource->r_named_buffer.nb_perm & EXCLAVES_BUFFER_PERM_WRITE,
	    !=, 0);

	__block user_addr_t src = _src;
	return exclaves_named_buffer_io(resource, offset, len,
	           ^(char *buffer, size_t size) {
		if (copyin(src, buffer, size) != 0) {
		        return KERN_FAILURE;
		}

		src += size;
		return KERN_SUCCESS;
	});
}

kern_return_t
exclaves_named_buffer_copyin(exclaves_resource_t *resource,
    user_addr_t buffer, mach_vm_size_t size1, mach_vm_size_t offset1,
    mach_vm_size_t size2, mach_vm_size_t offset2)
{
	assert3u(os_atomic_load(&resource->r_usecnt, relaxed), >, 0);
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_NAMED_BUFFER);

	mach_vm_size_t umax = 0;
	kern_return_t kr = KERN_FAILURE;

	if (buffer == USER_ADDR_NULL || size1 == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	named_buffer_resource_t *nb = &resource->r_named_buffer;
	assert3u(nb->nb_nranges, >, 0);
	assert3u(nb->nb_size, !=, 0);

	if (os_add_overflow(offset1, size1, &umax) || umax > nb->nb_size) {
		return KERN_INVALID_ARGUMENT;
	}

	if (os_add_overflow(offset2, size2, &umax) || umax > nb->nb_size) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((nb->nb_perm & EXCLAVES_BUFFER_PERM_WRITE) == 0) {
		return KERN_PROTECTION_FAILURE;
	}

	kr = exclaves_named_buffer_io_copyin(resource, buffer, offset1, size1);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	kr = exclaves_named_buffer_io_copyin(resource, buffer + size1, offset2,
	    size2);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	return KERN_SUCCESS;
}

static kern_return_t
exclaves_named_buffer_io_copyout(exclaves_resource_t *resource,
    user_addr_t _dst, off_t offset, size_t len)
{
	assert3u(resource->r_named_buffer.nb_perm & EXCLAVES_BUFFER_PERM_READ,
	    !=, 0);

	__block user_addr_t dst = _dst;
	return exclaves_named_buffer_io(resource, offset, len,
	           ^(char *buffer, size_t size) {
		if (copyout(buffer, dst, size) != 0) {
		        return KERN_FAILURE;
		}

		dst += size;
		return KERN_SUCCESS;
	});
}

kern_return_t
exclaves_named_buffer_copyout(exclaves_resource_t *resource,
    user_addr_t buffer, mach_vm_size_t size1, mach_vm_size_t offset1,
    mach_vm_size_t size2, mach_vm_size_t offset2)
{
	assert3u(os_atomic_load(&resource->r_usecnt, relaxed), >, 0);
	assert(resource->r_type == XNUPROXY_RESOURCE_NAMED_BUFFER ||
	    resource->r_type == XNUPROXY_RESOURCE_ARBITRATED_AUDIO_BUFFER);

	mach_vm_size_t umax = 0;
	kern_return_t kr = KERN_FAILURE;

	if (buffer == USER_ADDR_NULL || size1 == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	named_buffer_resource_t *nb = &resource->r_named_buffer;
	assert3u(nb->nb_nranges, >, 0);
	assert3u(nb->nb_size, !=, 0);

	if (os_add_overflow(offset1, size1, &umax) || umax > nb->nb_size) {
		return KERN_INVALID_ARGUMENT;
	}

	if (os_add_overflow(offset2, size2, &umax) || umax > nb->nb_size) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((nb->nb_perm & EXCLAVES_BUFFER_PERM_READ) == 0) {
		return KERN_PROTECTION_FAILURE;
	}

	kr = exclaves_named_buffer_io_copyout(resource, buffer, offset1, size1);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	kr = exclaves_named_buffer_io_copyout(resource, buffer + size1,
	    offset2, size2);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	return KERN_SUCCESS;
}

static void
named_buffer_unmap(exclaves_resource_t *resource)
{
	assert(resource->r_type == XNUPROXY_RESOURCE_ARBITRATED_AUDIO_BUFFER ||
	    resource->r_type == XNUPROXY_RESOURCE_NAMED_BUFFER);
	LCK_MTX_ASSERT(&resource->r_mutex, LCK_MTX_ASSERT_OWNED);

	/* BEGIN IGNORE CODESTYLE */
	resource->r_type == XNUPROXY_RESOURCE_NAMED_BUFFER ?
	    exclaves_named_buffer_unmap(resource) :
	    exclaves_audio_buffer_delete(resource);
	/* END IGNORE CODESTYLE */
}

static kern_return_t
named_buffer_map(exclaves_resource_t *resource, size_t size,
    exclaves_buffer_perm_t perm)
{
	assert(resource->r_type == XNUPROXY_RESOURCE_ARBITRATED_AUDIO_BUFFER ||
	    resource->r_type == XNUPROXY_RESOURCE_NAMED_BUFFER);
	assert3u(perm & ~(EXCLAVES_BUFFER_PERM_READ | EXCLAVES_BUFFER_PERM_WRITE), ==, 0);

	xnuproxy_cmd_t cmd = 0;
	kern_return_t kr = KERN_FAILURE;
	uint32_t status = 0;

	if (size == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	/* round size up to nearest page */
	mach_vm_offset_t rounded_size = 0;
	if (mach_vm_round_page_overflow(size, &rounded_size)) {
		return KERN_INVALID_ARGUMENT;
	}

	lck_mtx_lock(&resource->r_mutex);

	/*
	 * If already active, bump the use count, check that the perms and size
	 * are compatible and return. Checking the use count is insufficient
	 * here as this can race with with a non-locked use count release.
	 */
	if (resource->r_active) {
		const named_buffer_resource_t *nb = &resource->r_named_buffer;

		/*
		 * When only inbound and outbound buffers are supported, the
		 * perm check should be updated to ensure that the perms match
		 * (rather than being a subset). */
		if (nb->nb_size < rounded_size ||
		    (nb->nb_perm & perm) == 0) {
			lck_mtx_unlock(&resource->r_mutex);
			return KERN_INVALID_ARGUMENT;
		}

		exclaves_resource_retain(resource);
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_SUCCESS;
	}

	cmd = resource->r_type == XNUPROXY_RESOURCE_ARBITRATED_AUDIO_BUFFER ?
	    XNUPROXY_CMD_AUDIO_BUFFER_MAP:
	    XNUPROXY_CMD_NAMED_BUFFER_MAP;
	xnuproxy_msg_t msg = {
		.cmd = cmd,
		.cmd_named_buf_map = (xnuproxy_cmd_named_buf_map_t) {
			.request.buffer_id = resource->r_id,
			.request.buffer_size = rounded_size,
		}
	};

	kr = exclaves_xnu_proxy_send(&msg, NULL);
	if (kr != KERN_SUCCESS) {
		lck_mtx_unlock(&resource->r_mutex);
		return kr;
	}
	status = msg.cmd_named_buf_map.response.status;
	if (status != XNUPROXY_NAMED_BUFFER_SUCCESS) {
		lck_mtx_unlock(&resource->r_mutex);
		return status == XNUPROXY_NAMED_BUFFER_EINVAL ?
		       KERN_INVALID_ARGUMENT : KERN_FAILURE;
	}

	/*
	 * From this point on named_buffer_unmap() must be called if
	 * something goes wrong so that the buffer will be properly unmapped.
	 */
	const bool ro = msg.cmd_named_buf_map.response.readonly != 0;
	switch (perm) {
	case EXCLAVES_BUFFER_PERM_READ:
		if (!ro) {
			named_buffer_unmap(resource);
			lck_mtx_unlock(&resource->r_mutex);
			return KERN_PROTECTION_FAILURE;
		}
		break;
	case EXCLAVES_BUFFER_PERM_WRITE:
		if (ro) {
			named_buffer_unmap(resource);
			lck_mtx_unlock(&resource->r_mutex);
			return KERN_PROTECTION_FAILURE;
		}
		break;
	/* Maintain backwards compatibility for named buffers (READ|WRITE) */
	case EXCLAVES_BUFFER_PERM_READ | EXCLAVES_BUFFER_PERM_WRITE:
		if (ro) {
			perm &= ~EXCLAVES_BUFFER_PERM_WRITE;
		}
		break;
	}

	named_buffer_resource_t *nb = &resource->r_named_buffer;
	nb->nb_size = rounded_size;
	nb->nb_perm = perm;

	/*
	 * The named buffer is now accessible by xnu. Discover the
	 * layout of the memory.
	 */
	const uint64_t count = rounded_size / PAGE_SIZE;
	uint32_t page = 0;
	cmd = resource->r_type == XNUPROXY_RESOURCE_ARBITRATED_AUDIO_BUFFER ?
	    XNUPROXY_CMD_AUDIO_BUFFER_LAYOUT:
	    XNUPROXY_CMD_NAMED_BUFFER_LAYOUT;
	while (page < count) {
		xnuproxy_msg_t layout_msg = {
			.cmd = cmd,
			.cmd_named_buf_layout = (xnuproxy_cmd_named_buf_layout_t) {
				.request.buffer_id = resource->r_id,
				.request.start = page,
				.request.npages = (uint32_t)count - page,
			}
		};

		kr = exclaves_xnu_proxy_send(&layout_msg, NULL);
		if (kr != KERN_SUCCESS) {
			named_buffer_unmap(resource);
			lck_mtx_unlock(&resource->r_mutex);
			return kr;
		}

		status = layout_msg.cmd_named_buf_layout.response.status;
		switch (status) {
		case XNUPROXY_NAMED_BUFFER_SUCCESS:
		case XNUPROXY_NAMED_BUFFER_ENOSPC:
			break;

		case XNUPROXY_NAMED_BUFFER_EINVAL:
			named_buffer_unmap(resource);
			lck_mtx_unlock(&resource->r_mutex);
			return KERN_INVALID_ARGUMENT;

		default:
			named_buffer_unmap(resource);
			lck_mtx_unlock(&resource->r_mutex);
			return KERN_FAILURE;
		}

		xnuproxy_named_buf_range_t *range =
		    layout_msg.cmd_named_buf_layout.response.range;
		uint32_t nranges =
		    layout_msg.cmd_named_buf_layout.response.nranges;

		if (nb->nb_nranges + nranges > EXCLAVES_SHARED_BUFFER_MAX_RANGES) {
			named_buffer_unmap(resource);
			lck_mtx_unlock(&resource->r_mutex);
			printf("exclaves: "
			    "fragmented named buffer can't fit\n");
			return KERN_FAILURE;
		}

		for (uint32_t i = 0; i < nranges; i++) {
			nb->nb_range[nb->nb_nranges].address =
			    (char *)phystokv(range[i].address);
			nb->nb_range[nb->nb_nranges].npages = range[i].npages;

			assert3p(nb->nb_range[nb->nb_nranges].address, !=,
			    NULL);

			nb->nb_nranges++;
			page += range[i].npages;
			assert3u(page, <=, count);
		}
	}

	exclaves_resource_retain(resource);
	resource->r_active = true;

	lck_mtx_unlock(&resource->r_mutex);

	return KERN_SUCCESS;
}

kern_return_t
exclaves_named_buffer_map(const char *domain, const char *name, size_t size,
    exclaves_buffer_perm_t perm, exclaves_resource_t **out)
{
	assert3p(out, !=, NULL);

	exclaves_resource_t *resource = exclaves_resource_lookup_by_name(domain,
	    name, XNUPROXY_RESOURCE_NAMED_BUFFER);
	if (resource == NULL) {
		return KERN_NOT_FOUND;
	}
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_NAMED_BUFFER);

	kern_return_t kr = named_buffer_map(resource, size, perm);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	*out = resource;
	return KERN_SUCCESS;
}

static void
exclaves_named_buffer_unmap(exclaves_resource_t *resource)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_NAMED_BUFFER);
	assert3u(os_atomic_load(&resource->r_usecnt, relaxed), ==, 0);
	LCK_MTX_ASSERT(&resource->r_mutex, LCK_MTX_ASSERT_OWNED);

	xnuproxy_msg_t msg = {
		.cmd = XNUPROXY_CMD_NAMED_BUFFER_DELETE,
		.cmd_named_buf_delete.request.buffer_id = resource->r_id,
	};

	kern_return_t kr = exclaves_xnu_proxy_send(&msg, NULL);
	if (kr != KERN_SUCCESS) {
		printf("exclaves: failed to delete named buffer: %s\n",
		    resource->r_name);
		return;
	}
	uint8_t status = msg.cmd_named_buf_delete.response.status;

	if (status != XNUPROXY_NAMED_BUFFER_SUCCESS) {
		printf("exclaves: failed to delete named buffer: %s, "
		    "status: %d\n", resource->r_name, status);
		return;
	}

	bzero(&resource->r_named_buffer, sizeof(resource->r_named_buffer));

	resource->r_active = false;
}

/* -------------------------------------------------------------------------- */
#pragma mark Audio buffers

kern_return_t
exclaves_audio_buffer_map(const char *domain, const char *name, size_t size,
    exclaves_resource_t **out)
{
	assert3p(out, !=, NULL);

	exclaves_resource_t *resource = exclaves_resource_lookup_by_name(domain,
	    name, XNUPROXY_RESOURCE_ARBITRATED_AUDIO_BUFFER);
	if (resource == NULL) {
		return KERN_NOT_FOUND;
	}
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_ARBITRATED_AUDIO_BUFFER);

	kern_return_t kr = named_buffer_map(resource, size,
	    EXCLAVES_BUFFER_PERM_READ);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	*out = resource;
	return KERN_SUCCESS;
}

static void
exclaves_audio_buffer_delete(exclaves_resource_t *resource)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_ARBITRATED_AUDIO_BUFFER);
	assert3u(os_atomic_load(&resource->r_usecnt, relaxed), ==, 0);
	LCK_MTX_ASSERT(&resource->r_mutex, LCK_MTX_ASSERT_OWNED);

	xnuproxy_msg_t msg = {
		.cmd = XNUPROXY_CMD_AUDIO_BUFFER_DELETE,
		.cmd_audio_buf_delete.request.buffer_id = resource->r_id,
	};

	kern_return_t kr = exclaves_xnu_proxy_send(&msg, NULL);
	if (kr != KERN_SUCCESS) {
		printf("exclaves: failed to delete audio buffer: %s\n",
		    resource->r_name);
		return;
	}
	uint8_t status = msg.cmd_audio_buf_delete.response.status;

	if (status != XNUPROXY_NAMED_BUFFER_SUCCESS) {
		printf("exclaves: failed to delete audio buffer: %s, "
		    "status: %d\n", resource->r_name, status);
		return;
	}

	bzero(&resource->r_named_buffer, sizeof(resource->r_named_buffer));
	resource->r_active = false;
}

kern_return_t
exclaves_audio_buffer_copyout(exclaves_resource_t *resource,
    user_addr_t buffer, mach_vm_size_t size1, mach_vm_size_t offset1,
    mach_vm_size_t size2, mach_vm_size_t offset2)
{
	assert3u(os_atomic_load(&resource->r_usecnt, relaxed), >, 0);
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_ARBITRATED_AUDIO_BUFFER);

	xnuproxy_msg_t msg = {
		.cmd = XNUPROXY_CMD_AUDIO_BUFFER_COPYOUT,
		.cmd_audio_buf_copyout.request.buffer_id = resource->r_id,
		.cmd_audio_buf_copyout.request.size1 = size1,
		.cmd_audio_buf_copyout.request.offset1 = offset1,
		.cmd_audio_buf_copyout.request.size2 = size2,
		.cmd_audio_buf_copyout.request.offset2 = offset2,
	};

	kern_return_t kr = exclaves_xnu_proxy_send(&msg, NULL);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	uint8_t status = msg.cmd_audio_buf_copyout.response.status;

	if (status != XNUPROXY_NAMED_BUFFER_SUCCESS) {
		if (status == XNUPROXY_NAMED_BUFFER_EINVAL) {
			return KERN_INVALID_ARGUMENT;
		}
		return KERN_FAILURE;
	}

	return exclaves_named_buffer_copyout(resource, buffer, size1, offset1,
	           size2, offset2);
}

/* -------------------------------------------------------------------------- */
#pragma mark Conclave Manager

static void
exclaves_conclave_init(exclaves_resource_t *resource)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_CONCLAVE_MANAGER);

	tb_client_connection_t connection = NULL;
	__assert_only kern_return_t kr = exclaves_conclave_launcher_init(resource->r_id,
	    &connection);
	assert3u(kr, ==, KERN_SUCCESS);

	conclave_resource_t *conclave = &resource->r_conclave;

	conclave->c_control = connection;
	conclave->c_state = CONCLAVE_S_NONE;
	conclave->c_task = TASK_NULL;
}

kern_return_t
exclaves_conclave_attach(const char *domain, const char *name, task_t task)
{
	assert3p(task, !=, TASK_NULL);

	exclaves_resource_t *resource = exclaves_resource_lookup_by_name(domain,
	    name, XNUPROXY_RESOURCE_CONCLAVE_MANAGER);
	if (resource == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_CONCLAVE_MANAGER);

	conclave_resource_t *conclave = &resource->r_conclave;

	lck_mtx_lock(&resource->r_mutex);

	if (conclave->c_state != CONCLAVE_S_NONE) {
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_INVALID_ARGUMENT;
	}

	task_reference(task);

	task->conclave = resource;

	conclave->c_task = task;
	conclave->c_state = CONCLAVE_S_ATTACHED;

	lck_mtx_unlock(&resource->r_mutex);

	return KERN_SUCCESS;
}

kern_return_t
exclaves_conclave_detach(exclaves_resource_t *resource, task_t task)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_CONCLAVE_MANAGER);

	conclave_resource_t *conclave = &resource->r_conclave;

	lck_mtx_lock(&resource->r_mutex);

	if (conclave->c_state != CONCLAVE_S_ATTACHED &&
	    conclave->c_state != CONCLAVE_S_STOPPED) {
		panic("Task %p trying to detach a conclave %p but it is in a "
		    "weird state", task, conclave);
	}

	assert3p(task->conclave, !=, NULL);
	assert3p(resource, ==, task->conclave);

	task->conclave = NULL;
	conclave->c_task = TASK_NULL;

	conclave->c_state = CONCLAVE_S_NONE;

	lck_mtx_unlock(&resource->r_mutex);

	task_deallocate(task);

	return KERN_SUCCESS;
}

kern_return_t
exclaves_conclave_inherit(exclaves_resource_t *resource, task_t old_task,
    task_t new_task)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_CONCLAVE_MANAGER);

	conclave_resource_t *conclave = &resource->r_conclave;

	lck_mtx_lock(&resource->r_mutex);

	assert3u(conclave->c_state, !=, CONCLAVE_S_NONE);

	assert3p(new_task->conclave, ==, NULL);
	assert3p(old_task->conclave, !=, NULL);
	assert3p(resource, ==, old_task->conclave);

	/* Only allow inheriting the conclave if it has not yet started. */
	if (conclave->c_state != CONCLAVE_S_ATTACHED) {
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_FAILURE;
	}

	old_task->conclave = NULL;

	task_reference(new_task);
	new_task->conclave = resource;

	conclave->c_task = new_task;

	lck_mtx_unlock(&resource->r_mutex);
	task_deallocate(old_task);

	return KERN_SUCCESS;
}

kern_return_t
exclaves_conclave_launch(exclaves_resource_t *resource)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_CONCLAVE_MANAGER);

	conclave_resource_t *conclave = &resource->r_conclave;

	lck_mtx_lock(&resource->r_mutex);

	if (conclave->c_state != CONCLAVE_S_ATTACHED) {
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_FAILURE;
	}

	conclave->c_state = CONCLAVE_S_LAUNCHING;
	lck_mtx_unlock(&resource->r_mutex);

	__assert_only kern_return_t ret =
	    exclaves_conclave_launcher_launch(conclave->c_control);
	assert3u(ret, ==, KERN_SUCCESS);

	lck_mtx_lock(&resource->r_mutex);
	/* Check if conclave stop is requested */
	if (conclave->c_state == CONCLAVE_S_STOP_REQUESTED) {
		conclave->c_state = CONCLAVE_S_STOPPING;
		lck_mtx_unlock(&resource->r_mutex);

		ret = exclaves_conclave_launcher_stop(conclave->c_control,
		    CONCLAVE_LAUNCHER_CONCLAVESTOPREASON_EXIT);
		assert3u(ret, ==, KERN_SUCCESS);

		lck_mtx_lock(&resource->r_mutex);
		conclave->c_state = CONCLAVE_S_STOPPED;
	} else {
		conclave->c_state = CONCLAVE_S_LAUNCHED;
	}
	lck_mtx_unlock(&resource->r_mutex);

	return KERN_SUCCESS;
}

kern_return_t
exclaves_conclave_lookup_resources(exclaves_resource_t *resource,
    struct exclaves_resource_user *conclave_resource_user, int resource_count)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_CONCLAVE_MANAGER);
	conclave_resource_t *conclave = &resource->r_conclave;
	lck_mtx_lock(&resource->r_mutex);

	if (conclave->c_state != CONCLAVE_S_LAUNCHED) {
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_FAILURE;
	}

	for (int i = 0; i < resource_count; i++) {
		exclaves_resource_t *service_resource =
		    exclaves_resource_lookup_by_name(resource->r_name,
		    conclave_resource_user[i].r_name,
		    XNUPROXY_RESOURCE_SERVICE);
		if (service_resource == NULL) {
			/*
			 * Fall back to checking the Darwin domain. This should
			 * be removed once conclaves are properly defined.
			 */
			service_resource = exclaves_resource_lookup_by_name(
				EXCLAVES_DOMAIN_DARWIN,
				conclave_resource_user[i].r_name,
				XNUPROXY_RESOURCE_SERVICE);
		}
		if (service_resource == NULL) {
			conclave_resource_user[i].r_id = 0;
			conclave_resource_user[i].r_port = MACH_PORT_NULL;
			continue;
		}

		conclave_resource_user[i].r_id = service_resource->r_id;
		conclave_resource_user[i].r_port = MACH_PORT_NULL;
	}

	lck_mtx_unlock(&resource->r_mutex);
	return KERN_SUCCESS;
}

kern_return_t
exclaves_conclave_stop(exclaves_resource_t *resource, bool gather_crash_bt)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_CONCLAVE_MANAGER);

	conclave_resource_t *conclave = &resource->r_conclave;

	uint32_t conclave_stop_reason = gather_crash_bt ?
	    CONCLAVE_LAUNCHER_CONCLAVESTOPREASON_KILLED :
	    CONCLAVE_LAUNCHER_CONCLAVESTOPREASON_EXIT;

	lck_mtx_lock(&resource->r_mutex);

	/* TBD Call stop on the conclave manager endpoint. */
	if (conclave->c_state == CONCLAVE_S_LAUNCHING) {
		/* If another thread is launching, just request a stop */
		conclave->c_state = CONCLAVE_S_STOP_REQUESTED;
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_SUCCESS;
	} else if (conclave->c_state == CONCLAVE_S_ATTACHED) {
		/* Change the state to stopped if the conclave was never started */
		conclave->c_state = CONCLAVE_S_STOPPED;
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_SUCCESS;
	} else if (conclave->c_state == CONCLAVE_S_STOPPING ||
	    conclave->c_state == CONCLAVE_S_STOPPED) {
		/* Upcall to stop the conclave might be in progress, bail out */
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_SUCCESS;
	}

	if (conclave->c_state != CONCLAVE_S_LAUNCHED) {
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_FAILURE;
	}

	conclave->c_state = CONCLAVE_S_STOPPING;
	lck_mtx_unlock(&resource->r_mutex);

	__assert_only kern_return_t kr =
	    exclaves_conclave_launcher_stop(conclave->c_control,
	    conclave_stop_reason);
	assert3u(kr, ==, KERN_SUCCESS);

	lck_mtx_lock(&resource->r_mutex);
	conclave->c_state = CONCLAVE_S_STOPPED;
	lck_mtx_unlock(&resource->r_mutex);

	return KERN_SUCCESS;
}

extern int exit_with_exclave_exception(void *p);

kern_return_t
exclaves_conclave_stop_upcall(exclaves_resource_t *resource, task_t task)
{
	assert3p(resource, !=, NULL);
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_CONCLAVE_MANAGER);

	conclave_resource_t *conclave = &resource->r_conclave;

	lck_mtx_lock(&resource->r_mutex);

	if (conclave->c_state == CONCLAVE_S_STOPPING || conclave->c_state == CONCLAVE_S_STOPPED) {
		/* Upcall to stop the conclave might be in progress, bail out */
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_SUCCESS;
	}

	if (conclave->c_state != CONCLAVE_S_LAUNCHED && conclave->c_state != CONCLAVE_S_LAUNCHING
	    && conclave->c_state != CONCLAVE_S_ATTACHED) {
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_FAILURE;
	}

	conclave->c_state = CONCLAVE_S_STOPPING;
	lck_mtx_unlock(&resource->r_mutex);

	exit_with_exclave_exception(get_bsdtask_info(task));

	lck_mtx_lock(&resource->r_mutex);
	conclave->c_state = CONCLAVE_S_STOPPED;
	lck_mtx_unlock(&resource->r_mutex);
	return KERN_SUCCESS;
}


/* -------------------------------------------------------------------------- */
#pragma mark Sensors

static void
exclaves_resource_sensor_reset(exclaves_resource_t *resource)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_SENSOR);
	assert3u(os_atomic_load(&resource->r_usecnt, relaxed), ==, 0);
	LCK_MTX_ASSERT(&resource->r_mutex, LCK_MTX_ASSERT_OWNED);

	exclaves_sensor_status_t status;

	for (int i = 0; i < resource->r_sensor.s_startcount; i++) {
		__assert_only kern_return_t kr = exclaves_sensor_stop(
			(exclaves_sensor_type_t)resource->r_id, 0, &status);
		assert3u(kr, !=, KERN_INVALID_ARGUMENT);
	}

	resource->r_sensor.s_startcount = 0;
}

kern_return_t
exclaves_resource_sensor_open(const char *domain, const char *id_name,
    exclaves_resource_t **out)
{
	assert3p(out, !=, NULL);

	exclaves_resource_t *sensor = exclaves_resource_lookup_by_name(domain,
	    id_name, XNUPROXY_RESOURCE_SENSOR);

	if (sensor == NULL) {
		return KERN_NOT_FOUND;
	}

	assert3u(sensor->r_type, ==, XNUPROXY_RESOURCE_SENSOR);

	lck_mtx_lock(&sensor->r_mutex);
	exclaves_resource_retain(sensor);
	lck_mtx_unlock(&sensor->r_mutex);

	*out = sensor;

	return KERN_SUCCESS;
}

kern_return_t
exclaves_resource_sensor_start(exclaves_resource_t *resource, uint64_t flags,
    exclaves_sensor_status_t *status)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_SENSOR);

	lck_mtx_lock(&resource->r_mutex);
	if (resource->r_sensor.s_startcount == UINT64_MAX) {
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_INVALID_ARGUMENT;
	}

	kern_return_t kr = exclaves_sensor_start(
		(exclaves_sensor_type_t)resource->r_id, flags, status);
	if (kr == KERN_SUCCESS) {
		resource->r_sensor.s_startcount += 1;
	}
	lck_mtx_unlock(&resource->r_mutex);
	return kr;
}

kern_return_t
exclaves_resource_sensor_status(exclaves_resource_t *resource, uint64_t flags,
    exclaves_sensor_status_t *status)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_SENSOR);

	lck_mtx_lock(&resource->r_mutex);
	kern_return_t kr = exclaves_sensor_status(
		(exclaves_sensor_type_t)resource->r_id, flags, status);
	lck_mtx_unlock(&resource->r_mutex);

	return kr;
}

kern_return_t
exclaves_resource_sensor_stop(exclaves_resource_t *resource, uint64_t flags,
    exclaves_sensor_status_t *status)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_SENSOR);

	lck_mtx_lock(&resource->r_mutex);
	if (resource->r_sensor.s_startcount == 0) {
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_INVALID_ARGUMENT;
	}

	kern_return_t kr = exclaves_sensor_stop(
		(exclaves_sensor_type_t)resource->r_id, flags, status);
	if (kr == KERN_SUCCESS) {
		resource->r_sensor.s_startcount -= 1;
	}
	lck_mtx_unlock(&resource->r_mutex);

	return kr;
}

/* -------------------------------------------------------------------------- */
#pragma mark Notifications

static void
exclaves_notification_init(exclaves_resource_t *resource)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_NOTIFICATION);
	exclaves_notification_t *notification = &resource->r_notification;
	klist_init(&notification->notification_klist);
}

static int
filt_exclaves_notification_attach(struct knote *kn, __unused struct kevent_qos_s *kev)
{
	int error = 0;
	exclaves_resource_t *exclaves_resource = NULL;
	kern_return_t kr = exclaves_resource_from_port_name(current_space(), (mach_port_name_t)kn->kn_id, &exclaves_resource);
	if (kr != KERN_SUCCESS) {
		error = ENOENT;
		goto out;
	}
	assert3p(exclaves_resource, !=, NULL);
	if (exclaves_resource->r_type != XNUPROXY_RESOURCE_NOTIFICATION) {
		exclaves_resource_release(exclaves_resource);
		error = EINVAL;
		goto out;
	}

	lck_mtx_lock(&exclaves_resource->r_mutex);

	if (kn->kn_exclaves_resource != NULL) {
		lck_mtx_unlock(&exclaves_resource->r_mutex);
		exclaves_resource_release(exclaves_resource);
		error = EBUSY;
		goto out;
	}

	/* kn_exclaves_resource consumes the ref. */
	kn->kn_exclaves_resource = exclaves_resource;
	KNOTE_ATTACH(&exclaves_resource->r_notification.notification_klist, kn);
	lck_mtx_unlock(&exclaves_resource->r_mutex);

	error = 0;
out:
	return error;
}

static void
filt_exclaves_notification_detach(struct knote *kn)
{
	exclaves_resource_t *exclaves_resource = kn->kn_exclaves_resource;

	if (exclaves_resource != NULL) {
		assert3u(exclaves_resource->r_type, ==, XNUPROXY_RESOURCE_NOTIFICATION);
		lck_mtx_lock(&exclaves_resource->r_mutex);
		kn->kn_exclaves_resource = NULL;
		KNOTE_DETACH(&exclaves_resource->r_notification.notification_klist, kn);
		lck_mtx_unlock(&exclaves_resource->r_mutex);

		exclaves_resource_release(exclaves_resource);
	}
}

static int
filt_exclaves_notification_event(struct knote *kn, long hint)
{
	/* ALWAYS CALLED WITH exclaves_resource mutex held */
	exclaves_resource_t *exclaves_resource __assert_only = kn->kn_exclaves_resource;
	LCK_MTX_ASSERT(&exclaves_resource->r_mutex, LCK_MTX_ASSERT_OWNED);

	/*
	 * if the user is interested in this event, record it.
	 */
	if (kn->kn_sfflags & hint) {
		kn->kn_fflags |= hint;
	}

	/* if we have any matching state, activate the knote */
	if (kn->kn_fflags != 0) {
		return FILTER_ACTIVE;
	} else {
		return 0;
	}
}

static int
filt_exclaves_notification_touch(struct knote *kn, struct kevent_qos_s *kev)
{
	int result;
	exclaves_resource_t *exclaves_resource = kn->kn_exclaves_resource;
	assert3p(exclaves_resource, !=, NULL);
	assert3u(exclaves_resource->r_type, ==, XNUPROXY_RESOURCE_NOTIFICATION);

	lck_mtx_lock(&exclaves_resource->r_mutex);
	/* accept new mask and mask off output events no long interesting */
	kn->kn_sfflags = kev->fflags;
	kn->kn_fflags &= kn->kn_sfflags;
	if (kn->kn_fflags != 0) {
		result = FILTER_ACTIVE;
	} else {
		result = 0;
	}
	lck_mtx_unlock(&exclaves_resource->r_mutex);

	return result;
}

static int
filt_exclaves_notification_process(struct knote *kn, struct kevent_qos_s *kev)
{
	int result = 0;
	exclaves_resource_t *exclaves_resource = kn->kn_exclaves_resource;
	assert3p(exclaves_resource, !=, NULL);
	assert3u(exclaves_resource->r_type, ==, XNUPROXY_RESOURCE_NOTIFICATION);

	lck_mtx_lock(&exclaves_resource->r_mutex);
	if (kn->kn_fflags) {
		knote_fill_kevent(kn, kev, 0);
		result = FILTER_ACTIVE;
	}
	lck_mtx_unlock(&exclaves_resource->r_mutex);
	return result;
}

SECURITY_READ_ONLY_EARLY(struct filterops) exclaves_notification_filtops = {
	.f_attach  = filt_exclaves_notification_attach,
	.f_detach  = filt_exclaves_notification_detach,
	.f_event   = filt_exclaves_notification_event,
	.f_touch   = filt_exclaves_notification_touch,
	.f_process = filt_exclaves_notification_process,
};

kern_return_t
exclaves_notification_create(const char *domain, const char *name,
    exclaves_resource_t **out)
{
	assert3p(out, !=, NULL);

	exclaves_resource_t *resource = exclaves_resource_lookup_by_name(domain,
	    name, XNUPROXY_RESOURCE_NOTIFICATION);

	if (resource == NULL) {
		return KERN_NOT_FOUND;
	}
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_NOTIFICATION);

	lck_mtx_lock(&resource->r_mutex);
	exclaves_resource_retain(resource);
	lck_mtx_unlock(&resource->r_mutex);

	*out = resource;

	return KERN_SUCCESS;
}

kern_return_t
exclaves_notification_signal(exclaves_resource_t *exclaves_resource, long event_mask)
{
	assert3p(exclaves_resource, !=, NULL);
	assert3u(exclaves_resource->r_type, ==, XNUPROXY_RESOURCE_NOTIFICATION);

	lck_mtx_lock(&exclaves_resource->r_mutex);
	KNOTE(&exclaves_resource->r_notification.notification_klist, event_mask);
	lck_mtx_unlock(&exclaves_resource->r_mutex);

	return KERN_SUCCESS;
}

exclaves_resource_t *
exclaves_notification_lookup_by_id(const char *domain, uint64_t id)
{
	return exclaves_resource_lookup_by_id(domain, id,
	           XNUPROXY_RESOURCE_NOTIFICATION);
}

uint64_t
exclaves_service_lookup(const char *domain, const char *name)
{
	assert3p(domain, !=, NULL);
	assert3p(name, !=, NULL);

	exclaves_resource_t *resource = exclaves_resource_lookup_by_name(domain,
	    name, XNUPROXY_RESOURCE_SERVICE);
	if (resource == NULL) {
		return UINT64_C(~0);
	}

	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_SERVICE);
	return resource->r_id;
}

kern_return_t
exclaves_xnu_proxy_check_mem_usage(void)
{
	xnuproxy_msg_t msg = {
		.cmd = XNUPROXY_CMD_REPORT_MEMORY_USAGE,
	};

	return exclaves_xnu_proxy_send(&msg, NULL);
}

/* -------------------------------------------------------------------------- */
#pragma mark Shared Memory

int
exclaves_resource_shared_memory_io(exclaves_resource_t *resource, off_t offset,
    size_t len, int (^cb)(char *, size_t))
{
	assert(resource->r_type == XNUPROXY_RESOURCE_SHARED_MEMORY ||
	    resource->r_type == XNUPROXY_RESOURCE_ARBITRATED_AUDIO_MEMORY);
	assert3u(os_atomic_load(&resource->r_usecnt, relaxed), >, 0);

	shared_memory_resource_t *sm = &resource->r_shared_memory;
	assert3u(sm->sm_nranges, >, 0);
	assert3u(sm->sm_size, !=, 0);
	assert3u(offset + len, <=, sm->sm_size);

	for (int i = 0; i < sm->sm_nranges; i++) {
		/* Skip forward to the starting range. */
		if (offset >= sm->sm_range[i].npages * PAGE_SIZE) {
			offset -= sm->sm_range[i].npages * PAGE_SIZE;
			continue;
		}

		size_t size = MIN((sm->sm_range[i].npages * PAGE_SIZE) - offset, len);
		int ret = cb(sm->sm_range[i].address + offset, size);
		if (ret != 0) {
			return ret;
		}

		offset = 0;
		len -= size;

		if (len == 0) {
			break;
		}
	}
	assert3u(len, ==, 0);

	return 0;
}

static kern_return_t
exclaves_resource_shared_memory_io_copyin(exclaves_resource_t *resource,
    user_addr_t _src, off_t offset, size_t len)
{
	assert3u(resource->r_shared_memory.sm_perm & EXCLAVES_BUFFER_PERM_WRITE,
	    !=, 0);

	__block user_addr_t src = _src;
	return exclaves_resource_shared_memory_io(resource, offset, len,
	           ^(char *buffer, size_t size) {
		if (copyin(src, buffer, size) != 0) {
		        return KERN_FAILURE;
		}

		src += size;
		return KERN_SUCCESS;
	});
}

kern_return_t
exclaves_resource_shared_memory_copyin(exclaves_resource_t *resource,
    user_addr_t buffer, mach_vm_size_t size1, mach_vm_size_t offset1,
    mach_vm_size_t size2, mach_vm_size_t offset2)
{
	assert3u(os_atomic_load(&resource->r_usecnt, relaxed), >, 0);
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_SHARED_MEMORY);

	mach_vm_size_t umax = 0;
	kern_return_t kr = KERN_FAILURE;

	if (buffer == USER_ADDR_NULL || size1 == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	shared_memory_resource_t *sm = &resource->r_shared_memory;
	assert3u(sm->sm_nranges, >, 0);
	assert3u(sm->sm_size, !=, 0);

	if (os_add_overflow(offset1, size1, &umax) || umax > sm->sm_size) {
		return KERN_INVALID_ARGUMENT;
	}

	if (os_add_overflow(offset2, size2, &umax) || umax > sm->sm_size) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((sm->sm_perm & EXCLAVES_BUFFER_PERM_WRITE) == 0) {
		return KERN_PROTECTION_FAILURE;
	}

	kr = exclaves_resource_shared_memory_io_copyin(resource, buffer, offset1, size1);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	kr = exclaves_resource_shared_memory_io_copyin(resource, buffer + size1, offset2,
	    size2);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	return KERN_SUCCESS;
}

static kern_return_t
exclaves_resource_shared_memory_io_copyout(exclaves_resource_t *resource,
    user_addr_t _dst, off_t offset, size_t len)
{
	assert3u(resource->r_shared_memory.sm_perm & EXCLAVES_BUFFER_PERM_READ,
	    !=, 0);

	__block user_addr_t dst = _dst;
	return exclaves_resource_shared_memory_io(resource, offset, len,
	           ^(char *buffer, size_t size) {
		if (copyout(buffer, dst, size) != 0) {
		        return KERN_FAILURE;
		}

		dst += size;
		return KERN_SUCCESS;
	});
}

kern_return_t
exclaves_resource_shared_memory_copyout(exclaves_resource_t *resource,
    user_addr_t buffer, mach_vm_size_t size1, mach_vm_size_t offset1,
    mach_vm_size_t size2, mach_vm_size_t offset2)
{
	assert3u(os_atomic_load(&resource->r_usecnt, relaxed), >, 0);
	assert(resource->r_type == XNUPROXY_RESOURCE_SHARED_MEMORY ||
	    resource->r_type == XNUPROXY_RESOURCE_ARBITRATED_AUDIO_MEMORY);

	mach_vm_size_t umax = 0;
	kern_return_t kr = KERN_FAILURE;

	if (buffer == USER_ADDR_NULL || size1 == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	shared_memory_resource_t *sm = &resource->r_shared_memory;
	assert3u(sm->sm_nranges, >, 0);
	assert3u(sm->sm_size, !=, 0);

	if (os_add_overflow(offset1, size1, &umax) || umax > sm->sm_size) {
		return KERN_INVALID_ARGUMENT;
	}

	if (os_add_overflow(offset2, size2, &umax) || umax > sm->sm_size) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((sm->sm_perm & EXCLAVES_BUFFER_PERM_READ) == 0) {
		return KERN_PROTECTION_FAILURE;
	}

	kr = exclaves_resource_shared_memory_io_copyout(resource, buffer, offset1, size1);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	kr = exclaves_resource_shared_memory_io_copyout(resource, buffer + size1,
	    offset2, size2);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	return KERN_SUCCESS;
}

/* The lower 32bits contain the endpoint id. */
static uint32_t
audio_memory_get_endpoint(exclaves_resource_t *resource)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_ARBITRATED_AUDIO_MEMORY);
	return resource->r_id << 32 >> 32;
}

/* The upper 32bits of the id contain the buffer id. */
static uint32_t
audio_memory_get_buffer_id(exclaves_resource_t *resource)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_ARBITRATED_AUDIO_MEMORY);
	return resource->r_id >> 32;
}

static kern_return_t
shared_memory_map(exclaves_resource_t *resource, size_t size,
    exclaves_buffer_perm_t perm)
{
	assert(resource->r_type == XNUPROXY_RESOURCE_SHARED_MEMORY ||
	    resource->r_type == XNUPROXY_RESOURCE_ARBITRATED_AUDIO_MEMORY);
	assert3u(perm & ~(EXCLAVES_BUFFER_PERM_READ | EXCLAVES_BUFFER_PERM_WRITE), ==, 0);

	kern_return_t kr = KERN_FAILURE;

	/* round size up to nearest page */
	mach_vm_offset_t rounded_size = 0;
	if (size == 0 || mach_vm_round_page_overflow(size, &rounded_size)) {
		return KERN_INVALID_ARGUMENT;
	}

	lck_mtx_lock(&resource->r_mutex);

	__block shared_memory_resource_t *sm = &resource->r_shared_memory;

	/*
	 * If already active, bump the use count, check that the perms and size
	 * are compatible and return. Checking the use count is insufficient
	 * here as this can race with with a non-locked use count release.
	 */
	if (resource->r_active) {
		/*
		 * Both the permissions and size must match.
		 */
		if (sm->sm_size < rounded_size || sm->sm_perm != perm) {
			lck_mtx_unlock(&resource->r_mutex);
			return KERN_INVALID_ARGUMENT;
		}

		exclaves_resource_retain(resource);
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_SUCCESS;
	}

	/* This is lazily initialised and never de-initialised. */
	if (sm->sm_client.connection == NULL) {
		uint64_t endpoint = resource->r_type == XNUPROXY_RESOURCE_SHARED_MEMORY ?
		    resource->r_id :
		    audio_memory_get_endpoint(resource);

		kr = exclaves_shared_memory_init(endpoint, &sm->sm_client);
		if (kr != KERN_SUCCESS) {
			lck_mtx_unlock(&resource->r_mutex);
			return kr;
		}
	}

	const sharedmemorybase_perms_s sm_perm = perm == EXCLAVES_BUFFER_PERM_WRITE ?
	    SHAREDMEMORYBASE_PERMS_READWRITE : SHAREDMEMORYBASE_PERMS_READONLY;
	sharedmemorybase_mapping_s mapping = 0;
	kr = exclaves_shared_memory_setup(&sm->sm_client, sm_perm, 0,
	    rounded_size / PAGE_SIZE, &mapping);
	if (kr != KERN_SUCCESS) {
		lck_mtx_unlock(&resource->r_mutex);
		return kr;
	}

	/*
	 * From this point on exclaves_shared_memory_teardown() must be called
	 * if something goes wrong so that the buffer will be properly unmapped.
	 */
	sm->sm_size = rounded_size;
	sm->sm_perm = perm;
	sm->sm_nranges = 0;

	/*
	 * The shared buffer is now accessible by xnu. Discover the layout of
	 * the memory.
	 */
	__block bool success = true;
	kr = exclaves_shared_memory_iterate(&sm->sm_client, &mapping, 0,
	    rounded_size / PAGE_SIZE, ^(uint64_t pa) {
		char *vaddr = (char *)phystokv(pa);
		assert3p(vaddr, !=, NULL);

		/*
		 * If this virtual address is adjacent to the previous
		 * one, just extend the current range.
		 */
		if (sm->sm_nranges > 0) {
		        const size_t len = sm->sm_range[sm->sm_nranges - 1].npages * PAGE_SIZE;
		        const char *addr = sm->sm_range[sm->sm_nranges - 1].address + len;

		        if (vaddr == addr) {
		                sm->sm_range[sm->sm_nranges - 1].npages++;
		                return;
			}

		        if (sm->sm_nranges == EXCLAVES_SHARED_BUFFER_MAX_RANGES - 1) {
		                (void) printf("exclaves: too many ranges, can't fit\n");
		                success = false;
		                return;
			}
		}

		/*
		 * Page is not virtually contiguous with the previous one -
		 * stick it in a new range.
		 */
		sm->sm_range[sm->sm_nranges].npages = 1;
		sm->sm_range[sm->sm_nranges].address = vaddr;
		sm->sm_nranges++;
	});
	if (kr != KERN_SUCCESS || !success) {
		exclaves_shared_memory_teardown(&sm->sm_client, &mapping);
		lck_mtx_unlock(&resource->r_mutex);
		return KERN_FAILURE;
	}

	sm->sm_mapping = mapping;

	exclaves_resource_retain(resource);
	resource->r_active = true;

	lck_mtx_unlock(&resource->r_mutex);

	return KERN_SUCCESS;
}

kern_return_t
exclaves_resource_shared_memory_map(const char *domain, const char *name, size_t size,
    exclaves_buffer_perm_t perm, exclaves_resource_t **out)
{
	assert3p(out, !=, NULL);

	exclaves_resource_t *resource = exclaves_resource_lookup_by_name(domain,
	    name, XNUPROXY_RESOURCE_SHARED_MEMORY);
	if (resource == NULL) {
		return KERN_NOT_FOUND;
	}
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_SHARED_MEMORY);

	kern_return_t kr = shared_memory_map(resource, size, perm);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	*out = resource;
	return KERN_SUCCESS;
}


static void
exclaves_resource_shared_memory_unmap(exclaves_resource_t *resource)
{
	assert(resource->r_type == XNUPROXY_RESOURCE_SHARED_MEMORY ||
	    resource->r_type == XNUPROXY_RESOURCE_ARBITRATED_AUDIO_MEMORY);
	assert3u(os_atomic_load(&resource->r_usecnt, relaxed), ==, 0);
	LCK_MTX_ASSERT(&resource->r_mutex, LCK_MTX_ASSERT_OWNED);

	shared_memory_resource_t *sm = &resource->r_shared_memory;

	kern_return_t kr = exclaves_shared_memory_teardown(&sm->sm_client,
	    &sm->sm_mapping);
	if (kr != KERN_SUCCESS) {
		printf("exclaves: failed to teardown shared memory: %s, \n",
		    resource->r_name);
		return;
	}

	bzero(&resource->r_shared_memory, sizeof(resource->r_shared_memory));

	resource->r_active = false;
}


/* -------------------------------------------------------------------------- */
#pragma mark Arbitrated Audio Memory

kern_return_t
exclaves_resource_audio_memory_map(const char *domain, const char *name,
    size_t size, exclaves_resource_t **out)
{
	assert3p(out, !=, NULL);

	exclaves_resource_t *resource = exclaves_resource_lookup_by_name(domain,
	    name, XNUPROXY_RESOURCE_ARBITRATED_AUDIO_MEMORY);
	if (resource == NULL) {
		return KERN_NOT_FOUND;
	}
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_ARBITRATED_AUDIO_MEMORY);

	kern_return_t kr = shared_memory_map(resource, size,
	    EXCLAVES_BUFFER_PERM_READ);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	*out = resource;
	return KERN_SUCCESS;
}

static void
exclaves_resource_audio_memory_unmap(exclaves_resource_t *resource)
{
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_ARBITRATED_AUDIO_MEMORY);
	assert3u(os_atomic_load(&resource->r_usecnt, relaxed), ==, 0);
	LCK_MTX_ASSERT(&resource->r_mutex, LCK_MTX_ASSERT_OWNED);

	exclaves_resource_shared_memory_unmap(resource);
}

static kern_return_t
copyout_zero(user_addr_t buffer, mach_vm_size_t size, mach_vm_size_t offset)
{
	static const char zero[PAGE_SIZE] = {0};

	while (size > 0) {
		size_t copy_size = MIN(size, sizeof(zero));
		if (copyout(zero, buffer + offset, copy_size) != 0) {
			return KERN_FAILURE;
		}

		offset += copy_size;
		size -= copy_size;
	}

	return KERN_SUCCESS;
}

kern_return_t
exclaves_resource_audio_memory_copyout(exclaves_resource_t *resource,
    user_addr_t buffer, mach_vm_size_t size1, mach_vm_size_t offset1,
    mach_vm_size_t size2, mach_vm_size_t offset2)
{
	assert3u(os_atomic_load(&resource->r_usecnt, relaxed), >, 0);
	assert3u(resource->r_type, ==, XNUPROXY_RESOURCE_ARBITRATED_AUDIO_MEMORY);

	kern_return_t kr = KERN_FAILURE;
	exclaves_sensor_status_t status;
	const uint32_t id = audio_memory_get_buffer_id(resource);

	kr = exclaves_sensor_copy(id, size1, offset1, size2, offset2, &status);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	if (status == EXCLAVES_SENSOR_STATUS_ALLOWED) {
		kr = exclaves_resource_shared_memory_copyout(resource, buffer,
		    size1, offset1, size2, offset2);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
	} else {
		/*
		 * This should be removed once the audio arbiter is properly
		 * switching buffers and instead we should always rely on the
		 * audio arbiter to do its job and make the data available or
		 * not.
		 */
		kr = copyout_zero(buffer, size1, offset1);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		kr = copyout_zero(buffer, size2, offset2);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
	}

	return KERN_SUCCESS;
}

#endif /* CONFIG_EXCLAVES */
