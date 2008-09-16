/**
 * @file
 * Real-Time Driver Model for Xenomai, device management
 *
 * @note Copyright (C) 2005 Jan Kiszka <jan.kiszka@web.de>
 * @note Copyright (C) 2005 Joerg Langenberg <joerg.langenberg@gmx.net>
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*!
 * @addtogroup driverapi
 * @{
 */

#include <linux/module.h>
#include <linux/delay.h>

#include "rtdm/internal.h"

#define SET_DEFAULT_OP(device, operation)				\
	(device).operation##_rt  = (void *)rtdm_no_support;		\
	(device).operation##_nrt = (void *)rtdm_no_support

#define SET_DEFAULT_OP_IF_NULL(device, operation)			\
	if (!(device).operation##_rt)					\
		(device).operation##_rt = (void *)rtdm_no_support;	\
	if (!(device).operation##_nrt)					\
		(device).operation##_nrt = (void *)rtdm_no_support

#define ANY_HANDLER(device, operation)					\
	((device).operation##_rt || (device).operation##_nrt)

unsigned int devname_hashtab_size = DEF_DEVNAME_HASHTAB_SIZE;
unsigned int protocol_hashtab_size = DEF_PROTO_HASHTAB_SIZE;
module_param(devname_hashtab_size, uint, 0400);
module_param(protocol_hashtab_size, uint, 0400);
MODULE_PARM_DESC(devname_hashtab_size,
		 "Size of hash table for named devices (must be power of 2)");
MODULE_PARM_DESC(protocol_hashtab_size,
		 "Size of hash table for protocol devices "
		 "(must be power of 2)");

struct list_head *rtdm_named_devices;	/* hash table */
struct list_head *rtdm_protocol_devices;	/* hash table */
static int name_hashkey_mask;
static int proto_hashkey_mask;

DECLARE_MUTEX(nrt_dev_lock);
DEFINE_XNLOCK(rt_dev_lock);

#ifndef MODULE
int rtdm_initialised = 0;
#endif /* !MODULE */

int rtdm_no_support(void)
{
	return -ENOSYS;
}

static inline int get_name_hash(const char *str, int limit, int hashkey_mask)
{
	int hash = 0;

	while (*str != 0) {
		hash += *str++;
		if (--limit == 0)
			break;
	}
	return hash & hashkey_mask;
}

static inline int get_proto_hash(int protocol_family, int socket_type)
{
	return protocol_family & proto_hashkey_mask;
}

static inline void rtdm_reference_device(struct rtdm_device *device)
{
	atomic_inc(&device->reserved.refcount);
}

struct rtdm_device *get_named_device(const char *name)
{
	struct list_head *entry;
	struct rtdm_device *device;
	int hashkey;
	spl_t s;

	hashkey = get_name_hash(name, RTDM_MAX_DEVNAME_LEN, name_hashkey_mask);

	xnlock_get_irqsave(&rt_dev_lock, s);

	list_for_each(entry, &rtdm_named_devices[hashkey]) {
		device = list_entry(entry, struct rtdm_device, reserved.entry);

		if (strcmp(name, device->device_name) == 0) {
			rtdm_reference_device(device);

			xnlock_put_irqrestore(&rt_dev_lock, s);

			return device;
		}
	}

	xnlock_put_irqrestore(&rt_dev_lock, s);

	return NULL;
}

struct rtdm_device *get_protocol_device(int protocol_family, int socket_type)
{
	struct list_head *entry;
	struct rtdm_device *device;
	int hashkey;
	spl_t s;

	hashkey = get_proto_hash(protocol_family, socket_type);

	xnlock_get_irqsave(&rt_dev_lock, s);

	list_for_each(entry, &rtdm_protocol_devices[hashkey]) {
		device = list_entry(entry, struct rtdm_device, reserved.entry);

		if ((device->protocol_family == protocol_family) &&
		    (device->socket_type == socket_type)) {
			rtdm_reference_device(device);

			xnlock_put_irqrestore(&rt_dev_lock, s);

			return device;
		}
	}

	xnlock_put_irqrestore(&rt_dev_lock, s);

	return NULL;
}

/*!
 * @ingroup driverapi
 * @defgroup devregister Device Registration Services
 * @{
 */

/**
 * @brief Register a RTDM device
 *
 * @param[in] device Pointer to structure describing the new device.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if the device structure contains invalid entries.
 * Check kernel log in this case.
 *
 * - -ENOMEM is returned if the context for an exclusive device cannot be
 * allocated.
 *
 * - -EEXIST is returned if the specified device name of protocol ID is
 * already in use.
 *
 * - -EAGAIN is returned if some /proc entry cannot be created.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 *
 * Rescheduling: never.
 */
int rtdm_dev_register(struct rtdm_device *device)
{
	int hashkey;
	spl_t s;
	struct list_head *entry;
	struct rtdm_device *existing_dev;
	int ret;

	/* Catch unsuccessful initialisation */
	if (!rtdm_initialised)
		return -ENOSYS;

	/* Sanity check: structure version */
	XENO_ASSERT(RTDM, device->struct_version == RTDM_DEVICE_STRUCT_VER,
		    xnlogerr("RTDM: invalid rtdm_device version (%d, "
			     "required %d)\n", device->struct_version,
			     RTDM_DEVICE_STRUCT_VER);
		    return -EINVAL;);

	/* Sanity check: proc_name specified? */
	XENO_ASSERT(RTDM, device->proc_name,
		    xnlogerr("RTDM: no /proc entry name specified\n");
		    return -EINVAL;);

	switch (device->device_flags & RTDM_DEVICE_TYPE_MASK) {
	case RTDM_NAMED_DEVICE:
		/* Sanity check: any open handler? */
		XENO_ASSERT(RTDM, ANY_HANDLER(*device, open),
			    xnlogerr("RTDM: missing open handler\n");
			    return -EINVAL;);
		SET_DEFAULT_OP_IF_NULL(*device, open);
		SET_DEFAULT_OP(*device, socket);
		break;

	case RTDM_PROTOCOL_DEVICE:
		/* Sanity check: any socket handler? */
		XENO_ASSERT(RTDM, ANY_HANDLER(*device, socket),
			    xnlogerr("RTDM: missing socket handler\n");
			    return -EINVAL;);
		SET_DEFAULT_OP_IF_NULL(*device, socket);
		SET_DEFAULT_OP(*device, open);
		break;

	default:
		return -EINVAL;
	}

	/* Sanity check: non-RT close handler?
	 * (Always required for forced cleanup) */
	if (!device->ops.close_nrt) {
		xnlogerr("RTDM: missing non-RT close handler\n");
		return -EINVAL;
	}
	if (!device->ops.close_rt)
		device->ops.close_rt = (void *)rtdm_no_support;

	SET_DEFAULT_OP_IF_NULL(device->ops, ioctl);
	SET_DEFAULT_OP_IF_NULL(device->ops, read);
	SET_DEFAULT_OP_IF_NULL(device->ops, write);
	SET_DEFAULT_OP_IF_NULL(device->ops, recvmsg);
	SET_DEFAULT_OP_IF_NULL(device->ops, sendmsg);

	atomic_set(&device->reserved.refcount, 0);
	device->reserved.exclusive_context = NULL;

	if (device->device_flags & RTDM_EXCLUSIVE) {
		device->reserved.exclusive_context =
		    kmalloc(sizeof(struct rtdm_dev_context) +
			    device->context_size, GFP_KERNEL);
		if (!device->reserved.exclusive_context) {
			xnlogerr("RTDM: no memory for exclusive context "
				 "(context size: %ld)\n",
				 (long)device->context_size);
			return -ENOMEM;
		}
		/* mark exclusive context as unused */
		device->reserved.exclusive_context->device = NULL;
	}

	down(&nrt_dev_lock);

	if ((device->device_flags & RTDM_DEVICE_TYPE_MASK) == RTDM_NAMED_DEVICE) {
		trace_mark(xn_rtdm_nameddev_register, "device %p name %s "
			   "flags %d class %d sub_class %d profile_version %d "
			   "driver_version %d", device, device->device_name,
			   device->device_flags, device->device_class,
			   device->device_sub_class, device->profile_version,
			   device->driver_version);

		hashkey =
		    get_name_hash(device->device_name, RTDM_MAX_DEVNAME_LEN,
				  name_hashkey_mask);

		list_for_each(entry, &rtdm_named_devices[hashkey]) {
			existing_dev =
			    list_entry(entry, struct rtdm_device,
				       reserved.entry);
			if (strcmp(device->device_name,
				   existing_dev->device_name) == 0) {
				ret = -EEXIST;
				goto err;
			}
		}

#ifdef CONFIG_PROC_FS
		if ((ret = rtdm_proc_register_device(device)) < 0)
			goto err;
#endif /* CONFIG_PROC_FS */

		xnlock_get_irqsave(&rt_dev_lock, s);
		list_add_tail(&device->reserved.entry,
			      &rtdm_named_devices[hashkey]);
		xnlock_put_irqrestore(&rt_dev_lock, s);

		up(&nrt_dev_lock);
	} else {
		trace_mark(xn_rtdm_protocol_register, "device %p "
			   "protocol_family %d socket_type %d flags %d "
			   "class %d sub_class %d profile_version %d "
			   "driver_version %d", device,
			   device->protocol_family, device->socket_type,
			   device->device_flags, device->device_class,
			   device->device_sub_class, device->profile_version,
			   device->driver_version);

		hashkey = get_proto_hash(device->protocol_family,
					 device->socket_type);

		list_for_each(entry, &rtdm_protocol_devices[hashkey]) {
			existing_dev =
			    list_entry(entry, struct rtdm_device,
				       reserved.entry);
			if ((device->protocol_family ==
			     existing_dev->protocol_family)
			    && (device->socket_type ==
				existing_dev->socket_type)) {
				xnlogerr("RTDM: protocol %u:%u already "
					 "exists\n", device->protocol_family,
					 device->socket_type);
				ret = -EEXIST;
				goto err;
			}
		}

#ifdef CONFIG_PROC_FS
		if ((ret = rtdm_proc_register_device(device)) < 0)
			goto err;
#endif /* CONFIG_PROC_FS */

		xnlock_get_irqsave(&rt_dev_lock, s);
		list_add_tail(&device->reserved.entry,
			      &rtdm_protocol_devices[hashkey]);
		xnlock_put_irqrestore(&rt_dev_lock, s);

		up(&nrt_dev_lock);
	}
	return 0;

err:
	up(&nrt_dev_lock);
	if (device->reserved.exclusive_context)
		kfree(device->reserved.exclusive_context);
	return ret;
}

EXPORT_SYMBOL(rtdm_dev_register);

/**
 * @brief Unregisters a RTDM device
 *
 * @param[in] device Pointer to structure describing the device to be
 * unregistered.
 * @param[in] poll_delay Polling delay in milliseconds to check repeatedly for
 * open instances of @a device, or 0 for non-blocking mode.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -ENODEV is returned if the device was not registered.
 *
 * - -EAGAIN is returned if the device is busy with open instances and 0 has
 * been passed for @a poll_delay.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 *
 * Rescheduling: never.
 */
int rtdm_dev_unregister(struct rtdm_device *device, unsigned int poll_delay)
{
	spl_t s;
	struct rtdm_device *reg_dev;
	unsigned long warned = 0;

	if (!rtdm_initialised)
		return -ENOSYS;

	if ((device->device_flags & RTDM_DEVICE_TYPE_MASK) == RTDM_NAMED_DEVICE)
		reg_dev = get_named_device(device->device_name);
	else
		reg_dev = get_protocol_device(device->protocol_family,
					      device->socket_type);
	if (!reg_dev)
		return -ENODEV;

	trace_mark(xn_rtdm_dev_unregister, "device %p poll_delay %u",
		   device, poll_delay);

	down(&nrt_dev_lock);
	xnlock_get_irqsave(&rt_dev_lock, s);

	while (atomic_read(&reg_dev->reserved.refcount) > 1) {
		xnlock_put_irqrestore(&rt_dev_lock, s);
		up(&nrt_dev_lock);

		if (!poll_delay) {
			rtdm_dereference_device(reg_dev);
			trace_mark(xn_rtdm_dev_busy, "device %p", device);
			return -EAGAIN;
		}

		if (!__test_and_set_bit(0, &warned))
			xnlogwarn("RTDM: device %s still in use - waiting for "
				  "release...\n", reg_dev->device_name);
		msleep(poll_delay);
		trace_mark(xn_rtdm_dev_poll, "device %p", device);

		down(&nrt_dev_lock);
		xnlock_get_irqsave(&rt_dev_lock, s);
	}

	list_del(&reg_dev->reserved.entry);

	xnlock_put_irqrestore(&rt_dev_lock, s);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("information", device->proc_entry);
	remove_proc_entry(device->proc_name, rtdm_proc_root);
#endif /* CONFIG_PROC_FS */

	up(&nrt_dev_lock);

	if (reg_dev->reserved.exclusive_context)
		kfree(device->reserved.exclusive_context);

	return 0;
}

EXPORT_SYMBOL(rtdm_dev_unregister);
/** @} */

int __init rtdm_dev_init(void)
{
	int i;

	name_hashkey_mask = devname_hashtab_size - 1;
	proto_hashkey_mask = protocol_hashtab_size - 1;
	if (((devname_hashtab_size & name_hashkey_mask) != 0) ||
	    ((protocol_hashtab_size & proto_hashkey_mask) != 0))
		return -EINVAL;

	rtdm_named_devices = (struct list_head *)
	    kmalloc(devname_hashtab_size * sizeof(struct list_head),
		    GFP_KERNEL);
	if (!rtdm_named_devices)
		return -ENOMEM;

	for (i = 0; i < devname_hashtab_size; i++)
		INIT_LIST_HEAD(&rtdm_named_devices[i]);

	rtdm_protocol_devices = (struct list_head *)
	    kmalloc(protocol_hashtab_size * sizeof(struct list_head),
		    GFP_KERNEL);
	if (!rtdm_protocol_devices) {
		kfree(rtdm_named_devices);
		return -ENOMEM;
	}

	for (i = 0; i < protocol_hashtab_size; i++)
		INIT_LIST_HEAD(&rtdm_protocol_devices[i]);

	return 0;
}

/*@}*/
