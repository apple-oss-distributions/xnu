// Copyright (c) 2020 Apple Inc. All rights reserved.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_START@
//
// This file contains Original Code and/or Modifications of Original Code
// as defined in and that are subject to the Apple Public Source License
// Version 2.0 (the 'License'). You may not use this file except in
// compliance with the License. The rights granted to you under the License
// may not be used to create, or enable the creation or redistribution of,
// unlawful or unlicensed copies of an Apple operating system, or to
// circumvent, violate, or enable the circumvention or violation of, any
// terms of an Apple operating system software license agreement.
//
// Please obtain a copy of the License at
// http://www.opensource.apple.com/apsl/ and read it before using this file.
//
// The Original Code and all software distributed under the License are
// distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
// EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
// Please see the License for the specific language governing rights and
// limitations under the License.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_END@

#include <kern/assert.h>
#include <kern/kalloc.h>
#include <kern/locks.h>
#include <kern/perfmon.h>
#include <libkern/copyio.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <stdbool.h>
#include <sys/param.h> /* NULL */
#include <sys/stat.h> /* dev_t */
#include <miscfs/devfs/devfs.h> /* must come after sys/stat.h */
#include <sys/conf.h> /* must come after sys/stat.h */
#include <sys/perfmon_private.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/types.h>

static unsigned int perfmon_dev_major_sources[perfmon_kind_max] = { 0 };
static const unsigned int PERFMON_DEVICES_MAX = 4;

LCK_GRP_DECLARE(perfmon_dev_lock_group, "perfmon");

// perfmon_device corresponds to each open file descriptor for perfmon's
// character devices.
struct perfmon_device {
	void *pmdv_copyout_buf;
	lck_mtx_t pmdv_mutex;
	perfmon_config_t pmdv_config;
	bool pmdv_allocated;
};

struct perfmon_device perfmon_devices[perfmon_kind_max][PERFMON_DEVICES_MAX]
        = { 0 };
// perfmon_devices is protected by perfmon_devices_lock.  If both a per-device
// mutex and the devices lock are taken together, the devices lock should be
// taken first.
LCK_MTX_DECLARE(perfmon_devices_lock, &perfmon_dev_lock_group);

static int
perfmon_dev_get_source_index(dev_t dev)
{
	int dmaj = major(dev);
	for (int i = 0; i < perfmon_kind_max; i++) {
		if (perfmon_dev_major_sources[i] == dmaj) {
			return i;
		}
	}
	panic("perfmon: no source for major device: 0x%x", dev);
}

static struct perfmon_device *
perfmon_dev_get_device(dev_t dev)
{
	int source_index = perfmon_dev_get_source_index(dev);
	int dmin = minor(dev);
	if (dmin >= perfmon_kind_max || dmin < 0) {
		panic("perfmon: invalid minor dev number: 0x%x", dev);
	}

	return &perfmon_devices[source_index][dmin];
}

static struct perfmon_source *
perfmon_dev_get_source(dev_t dev)
{
	return &perfmon_sources[perfmon_dev_get_source_index(dev)];
}

static size_t
perfmon_device_copyout_size(struct perfmon_source *source)
{
	struct perfmon_layout *layout = &source->ps_layout;
	size_t counters_size = layout->pl_counter_count * layout->pl_unit_count *
	    sizeof(uint64_t);
	size_t reg_names_size = layout->pl_reg_count * sizeof(perfmon_name_t);
	size_t reg_values_size = layout->pl_reg_count * layout->pl_unit_count *
	    sizeof(uint64_t);
	size_t attrs_size = layout->pl_attr_count * sizeof(struct perfmon_attr);

	return MAX(counters_size, MAX(reg_names_size,
	           MAX(attrs_size, reg_values_size)));
}

static int
perfmon_dev_open(dev_t dev, int flags, int __unused devtype, proc_t __unused p)
{
	lck_mtx_lock(&perfmon_devices_lock);
	struct perfmon_device *device = perfmon_dev_get_device(dev);
	struct perfmon_source *source = perfmon_dev_get_source(dev);
	if (((flags & O_RDWR) == O_RDWR)) {
		if (!perfmon_acquire(source->ps_kind, "perfmon")) {
			return ETXTBSY;
		}
	}
	if (device->pmdv_allocated) {
		return EMFILE;
	}
	if (!source->ps_supported) {
		panic("perfmon: attempt to open unsupported source: 0x%x", dev);
	}
	device->pmdv_allocated = true;
	device->pmdv_copyout_buf = kalloc_data(perfmon_device_copyout_size(source), Z_WAITOK);
	if ((flags & O_RDWR) == O_RDWR) {
		device->pmdv_config = perfmon_config_create(source);
	}
	lck_mtx_unlock(&perfmon_devices_lock);

	return 0;
}

static int
perfmon_dev_clone(dev_t dev, int action)
{
	int minor = 0;

	lck_mtx_lock(&perfmon_devices_lock);

	switch (action) {
	case DEVFS_CLONE_ALLOC:;
		int source_index = perfmon_dev_get_source_index(dev);
		for (unsigned int i = 0; i < PERFMON_DEVICES_MAX; i++) {
			struct perfmon_device *device = &perfmon_devices[source_index][i];
			if (!device->pmdv_allocated) {
				minor = i;
				break;
			}
		}
		// Returning non-zero from the alloc action hangs devfs, so let the open
		// handler figure out that EMFILE should be returned.
		break;
	case DEVFS_CLONE_FREE:
		// Nothing to do since a device wasn't allocated until the call to open.
		break;
	default:
		minor = -1;
		break;
	}

	lck_mtx_unlock(&perfmon_devices_lock);

	return minor;
}

static int
perfmon_dev_close(dev_t dev, int __unused flags, int __unused devtype,
    proc_t __unused p)
{
	lck_mtx_lock(&perfmon_devices_lock);

	struct perfmon_device *device = perfmon_dev_get_device(dev);

	lck_mtx_lock(&device->pmdv_mutex);

	if (!device->pmdv_allocated) {
		panic("perfmon: no device allocated to close: 0x%x", dev);
	}
	device->pmdv_allocated = false;
	struct perfmon_source *source = perfmon_dev_get_source(dev);
	kfree_data(device->pmdv_copyout_buf, perfmon_device_copyout_size(source));
	device->pmdv_copyout_buf = NULL;
	if (device->pmdv_config) {
		perfmon_release(source->ps_kind, "perfmon");
		perfmon_config_destroy(device->pmdv_config);
		device->pmdv_config = NULL;
	}

	lck_mtx_unlock(&device->pmdv_mutex);
	lck_mtx_unlock(&perfmon_devices_lock);

	return 0;
}

static int
perfmon_dev_ioctl(dev_t dev, unsigned long cmd, char *arg,
    int __unused fflag, proc_t __unused p)
{
	struct perfmon_device *device = perfmon_dev_get_device(dev);
	struct perfmon_source *source = perfmon_dev_get_source(dev);
	int ret = 0;

	lck_mtx_lock(&device->pmdv_mutex);

	unsigned short reg_count = source->ps_layout.pl_reg_count;
	unsigned short unit_count = source->ps_layout.pl_unit_count;

	switch (cmd) {
	case PERFMON_CTL_GET_LAYOUT:;
		struct perfmon_layout *layout = (void *)arg;
		*layout = source->ps_layout;
		ret = 0;
		break;

	case PERFMON_CTL_LIST_REGS: {
		user_addr_t uptr = *(user_addr_t *)(void *)arg;
		size_t names_size = reg_count * sizeof(source->ps_register_names[0]);
		ret = copyout(source->ps_register_names, uptr, names_size);
		break;
	}

	case PERFMON_CTL_SAMPLE_REGS: {
		user_addr_t uptr = *(user_addr_t *)(void *)arg;
		uint64_t *sample_buf = device->pmdv_copyout_buf;
		size_t sample_size = reg_count * unit_count * sizeof(sample_buf[0]);
		perfmon_source_sample_regs(source, sample_buf, reg_count);
		ret = copyout(sample_buf, uptr, sample_size);
		break;
	}

	case PERFMON_CTL_LIST_ATTRS: {
		user_addr_t uptr = *(user_addr_t *)(void *)arg;
		unsigned short attr_count = source->ps_layout.pl_attr_count;
		const perfmon_name_t *attrs_buf = source->ps_attribute_names;
		size_t attrs_size = attr_count * sizeof(attrs_buf[0]);
		ret = copyout(attrs_buf, uptr, attrs_size);
		break;
	}

	case PERFMON_CTL_ADD_EVENT:
		if (device->pmdv_config) {
			struct perfmon_event *event = (void *)arg;
			event->pe_name[sizeof(event->pe_name) - 1] = '\0';
			ret = perfmon_config_add_event(device->pmdv_config, event);
		} else {
			ret = EBADF;
		}
		break;

	case PERFMON_CTL_SET_ATTR:
		if (device->pmdv_config) {
			struct perfmon_attr *attr = (void *)arg;
			attr->pa_name[sizeof(attr->pa_name) - 1] = '\0';
			ret = perfmon_config_set_attr(device->pmdv_config, attr);
		} else {
			ret = EBADF;
		}
		break;

	case PERFMON_CTL_CONFIGURE:
		if (device->pmdv_config) {
			ret = perfmon_configure(device->pmdv_config);
		} else {
			ret = EBADF;
		}
		break;

	case PERFMON_CTL_START:
		ret = ENOTSUP;
		break;

	case PERFMON_CTL_STOP:
		ret = ENOTSUP;
		break;

	case PERFMON_CTL_SPECIFY:;
		struct perfmon_config *config = device->pmdv_config;
		if (config) {
			struct perfmon_spec *uspec = (void *)arg;
			struct perfmon_spec *kspec = perfmon_config_specify(config);
			if (uspec->ps_events) {
				ret = copyout(kspec->ps_events, (user_addr_t)uspec->ps_events,
				    MIN(uspec->ps_event_count, kspec->ps_event_count));
				if (0 == ret && uspec->ps_attrs) {
					ret = copyout(kspec->ps_attrs, (user_addr_t)uspec->ps_attrs,
					    MIN(uspec->ps_attr_count, kspec->ps_attr_count));
				}
			}
			uspec->ps_event_count = kspec->ps_event_count;
			uspec->ps_attr_count = kspec->ps_event_count;
		} else {
			ret = EBADF;
		}
		break;

	default:
		ret = ENOTSUP;
		break;
	}

	lck_mtx_unlock(&device->pmdv_mutex);

	return ret;
}

static const struct cdevsw perfmon_cdevsw = {
	.d_open = perfmon_dev_open, .d_close = perfmon_dev_close,
	.d_ioctl = perfmon_dev_ioctl,

	.d_read = eno_rdwrt, .d_write = eno_rdwrt, .d_stop = eno_stop,
	.d_reset = eno_reset, .d_ttys = NULL, .d_select = eno_select,
	.d_mmap = eno_mmap, .d_strategy = eno_strat, .d_type = 0,
};

int
perfmon_dev_init(void)
{
	for (unsigned int i = 0; i < perfmon_kind_max; i++) {
		struct perfmon_source *source = &perfmon_sources[i];
		if (!source->ps_supported) {
			continue;
		}

		int dmaj = cdevsw_add(-1, &perfmon_cdevsw);
		if (dmaj < 0) {
			panic("perfmon: %s: cdevsw_add failed: 0x%x", source->ps_name,
			    dmaj);
		}
		perfmon_dev_major_sources[i] = dmaj;
		void *node = devfs_make_node_clone(makedev(dmaj, 0), DEVFS_CHAR,
		    UID_ROOT, GID_WHEEL, 0666, perfmon_dev_clone, "perfmon_%s",
		    source->ps_name);
		if (!node) {
			panic("perfmon: %s: devfs_make_node_clone failed",
			    source->ps_name);
		}

		for (size_t j = 0; j < PERFMON_DEVICES_MAX; j++) {
			lck_mtx_init(&perfmon_devices[i][j].pmdv_mutex,
			    &perfmon_dev_lock_group, NULL);
		}
	}

	return 0;
}
