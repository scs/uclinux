/*
 * Copyright (C) 2005 Jan Kiszka <jan.kiszka@web.de>.
 * Copyright (C) 2005 Joerg Langenberg <joerg.langenberg@gmx.net>.
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

#include "rtdm/internal.h"

/* Derived from Erwin Rol's rtai_proc_fs.h.
   Assumes that output fits into the provided buffer. */

#define RTDM_PROC_PRINT_VARS(MAX_BLOCK_LEN)				\
	const int max_block_len = MAX_BLOCK_LEN;			\
	off_t __limit = count - MAX_BLOCK_LEN;				\
	int __len = 0;							\
									\
	*eof = 1;							\
	if (count < MAX_BLOCK_LEN)					\
		return 0

#define RTDM_PROC_PRINT(fmt, args...)					\
({									\
	__len += snprintf(buf + __len, max_block_len, fmt, ##args);	\
	(__len <= __limit);						\
})

#define RTDM_PROC_PRINT_DONE						\
	 return __len

struct proc_dir_entry *rtdm_proc_root;	/* /proc/xenomai/rtdm */

static int proc_read_named_devs(char *buf, char **start, off_t offset,
				int count, int *eof, void *data)
{
	int i;
	struct list_head *entry;
	struct rtdm_device *device;
	RTDM_PROC_PRINT_VARS(80);

	if (down_interruptible(&nrt_dev_lock))
		return -ERESTARTSYS;

	if (!RTDM_PROC_PRINT("Hash\tName\t\t\t\tDriver\t\t/proc\n"))
		goto done;

	for (i = 0; i < devname_hashtab_size; i++)
		list_for_each(entry, &rtdm_named_devices[i]) {
			device = list_entry(entry, struct rtdm_device,
					    reserved.entry);

			if (!RTDM_PROC_PRINT("%02X\t%-31s\t%-15s\t%s\n",
					     i, device->device_name,
					     device->driver_name,
					     device->proc_name))
				break;
		}

      done:
	up(&nrt_dev_lock);

	RTDM_PROC_PRINT_DONE;
}

static int proc_read_proto_devs(char *buf, char **start, off_t offset,
				int count, int *eof, void *data)
{
	int i;
	struct list_head *entry;
	struct rtdm_device *device;
	char txt[32];
	RTDM_PROC_PRINT_VARS(80);

	if (down_interruptible(&nrt_dev_lock))
		return -ERESTARTSYS;

	if (!RTDM_PROC_PRINT("Hash\tProtocolFamily:SocketType\tDriver\t\t"
			     "/proc\n"))
		goto done;

	for (i = 0; i < protocol_hashtab_size; i++)
		list_for_each(entry, &rtdm_protocol_devices[i]) {
			device = list_entry(entry, struct rtdm_device,
					    reserved.entry);

			snprintf(txt, sizeof(txt), "%u:%u",
				 device->protocol_family, device->socket_type);
			if (!RTDM_PROC_PRINT("%02X\t%-31s\t%-15s\t%s\n", i,
					     txt, device->driver_name,
					     device->proc_name))
				break;
		}

      done:
	up(&nrt_dev_lock);

	RTDM_PROC_PRINT_DONE;
}

static int proc_read_open_fildes(char *buf, char **start, off_t offset,
				 int count, int *eof, void *data)
{
	int i;
	int close_lock_count;
	struct rtdm_device *device;
	struct rtdm_process owner;
	spl_t s;
	RTDM_PROC_PRINT_VARS(80);

	if (!RTDM_PROC_PRINT("Index\tLocked\tDevice\t\tOwner [PID]\n"))
		goto done;

	if (down_interruptible(&nrt_dev_lock))
		return -ERESTARTSYS;

	for (i = 0; i < RTDM_FD_MAX; i++) {
		struct rtdm_dev_context *context;

		xnlock_get_irqsave(&rt_fildes_lock, s);

		context = fildes_table[i].context;
		if (!context) {
			xnlock_put_irqrestore(&rt_fildes_lock, s);
			continue;
		}

		close_lock_count = atomic_read(&context->close_lock_count);
		device = context->device;

		if (context->reserved.owner)
			memcpy(&owner, context->reserved.owner, sizeof(owner));
		else {
			strcpy(owner.name, "<kernel>");
			owner.pid = -1;
		}

		xnlock_put_irqrestore(&rt_fildes_lock, s);

		if (!RTDM_PROC_PRINT("%d\t%d\t%-15s %s [%d]\n", i,
				     close_lock_count,
				     (device->device_flags&RTDM_NAMED_DEVICE) ?
				     device->device_name : device->proc_name,
				     owner.name, owner.pid))
			break;
	}

	up(&nrt_dev_lock);

      done:
	RTDM_PROC_PRINT_DONE;
}

static int proc_kill_open_fildes(struct file *file, const char __user *buffer,
				 unsigned long count, void *data)
{
	char krnl_buf[32];
	int fd;
	int res;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	if (count >= sizeof(krnl_buf))
		return -EINVAL;

	if (copy_from_user(krnl_buf, buffer, count))
		return -EFAULT;
	krnl_buf[count] = '\0';

	if (!sscanf(krnl_buf, "%d", &fd))
		return -EINVAL;

	res = __rt_dev_close(current, fd);
	if (res < 0)
		return res;

	return count;
}

static int proc_read_fildes(char *buf, char **start, off_t offset,
			    int count, int *eof, void *data)
{
	RTDM_PROC_PRINT_VARS(80);

	RTDM_PROC_PRINT("total=%d:open=%d:free=%d\n", RTDM_FD_MAX,
			open_fildes, RTDM_FD_MAX - open_fildes);

	RTDM_PROC_PRINT_DONE;
}

static int proc_read_dev_info(char *buf, char **start, off_t offset,
			      int count, int *eof, void *data)
{
	/* accessing the device during unregister (remove_proc_entry) might be
	   racy, but no official workaround is known yet */
	struct rtdm_device *device = data;
	RTDM_PROC_PRINT_VARS(256);

	if (!RTDM_PROC_PRINT("driver:\t\t%s\nversion:\t%d.%d.%d\n",
			     device->driver_name,
			     RTDM_DRIVER_MAJOR_VER(device->driver_version),
			     RTDM_DRIVER_MINOR_VER(device->driver_version),
			     RTDM_DRIVER_PATCH_VER(device->driver_version)))
		goto done;
	if (!RTDM_PROC_PRINT("peripheral:\t%s\nprovider:\t%s\n",
			     device->peripheral_name, device->provider_name))
		goto done;
	if (!RTDM_PROC_PRINT("class:\t\t%d\nsub-class:\t%d\n",
			     device->device_class, device->device_sub_class))
		goto done;
	if (!RTDM_PROC_PRINT("flags:\t\t%s%s%s\n",
			     (device->device_flags & RTDM_EXCLUSIVE) ?
			     "EXCLUSIVE  " : "",
			     (device->device_flags & RTDM_NAMED_DEVICE) ?
			     "NAMED_DEVICE  " : "",
			     (device->device_flags & RTDM_PROTOCOL_DEVICE) ?
			     "PROTOCOL_DEVICE  " : ""))
		goto done;
	RTDM_PROC_PRINT("lock count:\t%d\n",
			atomic_read(&device->reserved.refcount));

      done:
	RTDM_PROC_PRINT_DONE;
}

int rtdm_proc_register_device(struct rtdm_device *device)
{
	struct proc_dir_entry *dev_dir;
	struct proc_dir_entry *proc_entry;

	dev_dir = create_proc_entry(device->proc_name, S_IFDIR, rtdm_proc_root);
	if (!dev_dir)
		goto err_out;

	proc_entry = create_proc_entry("information", S_IFREG | S_IRUGO,
				       dev_dir);
	if (!proc_entry) {
		remove_proc_entry(device->proc_name, rtdm_proc_root);
		goto err_out;
	}
	proc_entry->data = device;
	proc_entry->read_proc = proc_read_dev_info;

	device->proc_entry = dev_dir;

	return 0;

      err_out:
	xnlogerr("RTDM: error while creating device proc entry\n");
	return -EAGAIN;
}

int __init rtdm_proc_init(void)
{
	struct proc_dir_entry *proc_entry;

	/* Initialise /proc entries */
	rtdm_proc_root = create_proc_entry("xenomai/rtdm", S_IFDIR, NULL);
	if (!rtdm_proc_root)
		return -EAGAIN;

	proc_entry = create_proc_entry("named_devices", S_IFREG | S_IRUGO,
				       rtdm_proc_root);
	if (!proc_entry)
		return -EAGAIN;
	proc_entry->read_proc = proc_read_named_devs;

	proc_entry = create_proc_entry("protocol_devices", S_IFREG | S_IRUGO,
				       rtdm_proc_root);
	if (!proc_entry)
		return -EAGAIN;
	proc_entry->read_proc = proc_read_proto_devs;

	proc_entry =
	    create_proc_entry("open_fildes", S_IFREG | S_IRUGO, rtdm_proc_root);
	if (!proc_entry)
		return -EAGAIN;
	proc_entry->read_proc = proc_read_open_fildes;
	proc_entry->write_proc = proc_kill_open_fildes;

	proc_entry =
	    create_proc_entry("fildes", S_IFREG | S_IRUGO, rtdm_proc_root);
	if (!proc_entry)
		return -EAGAIN;
	proc_entry->read_proc = proc_read_fildes;

	return 0;
}

void rtdm_proc_cleanup(void)
{
	remove_proc_entry("fildes", rtdm_proc_root);
	remove_proc_entry("open_fildes", rtdm_proc_root);
	remove_proc_entry("protocol_devices", rtdm_proc_root);
	remove_proc_entry("named_devices", rtdm_proc_root);
	remove_proc_entry("xenomai/rtdm", NULL);
}
