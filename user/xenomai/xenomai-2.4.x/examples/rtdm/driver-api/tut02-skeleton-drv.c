/***************************************************************************
 *   Copyright (C) 2007 by trem (Philippe Reynes)                          *
 *   tremyfr@yahoo.fr                                                      *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

/**
 * This kernel driver demonstrates how an RTDM device can be called from
 * a RT task and how to use a semaphore to create a blocking device operation.
 *
 * It is a simple device, only 4 operation are provided:
 *  - open:  start device usage
 *  - close: ends device usage
 *  - write: store transfered data in an internal buffer (realtime context)
 *  - read:  return previously stored data and erase buffer (realtime context)
 *
 */

#include <linux/module.h>
#include <rtdm/rtdm_driver.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("trem");

#define SIZE_MAX			1024
#define DEVICE_NAME			"tut02-skeleton-drv01"
#define SOME_SUB_CLASS			4711

/**
 * The structure of the buffer
 *
 */
typedef struct buffer_s {
	int size;
	char data[SIZE_MAX];
} buffer_t;

/**
 * The global buffer
 *
 */
buffer_t buffer;

/**
 * The global semaphore
 *
 */
rtdm_sem_t sem;

/**
 * Open the device
 *
 * This function is called when the device shall be opened.
 *
 */
static int simple_rtdm_open(struct rtdm_dev_context *context,
				rtdm_user_info_t * user_info, int oflags)
{
	return 0;
}

/**
 * Close the device
 *
 * This function is called when the device shall be closed.
 *
 */
static int simple_rtdm_close(struct rtdm_dev_context *context,
				rtdm_user_info_t * user_info)
{
	return 0;
}

/**
 * Read from the device
 *
 * This function is called when the device is read in realtime context.
 *
 */
static ssize_t simple_rtdm_read_rt(struct rtdm_dev_context *context,
				    rtdm_user_info_t * user_info, void *buf,
				    size_t nbyte)
{
	int ret, size;

	/* take the semaphore */
	rtdm_sem_down(&sem);

	/* read the kernel buffer and sent it to user space */
	size = (buffer.size > nbyte) ? nbyte : buffer.size;
	ret = rtdm_safe_copy_to_user(user_info, buf, buffer.data, size);

	/* if an error has occured, send it to user */
	if (ret)
		return ret;

	/* clean the kernel buffer */
	buffer.size = 0;

	return size;
}

/**
 * Write in the device
 *
 * This function is called when the device is written in realtime context.
 *
 */
static ssize_t simple_rtdm_write_rt(struct rtdm_dev_context *context,
				     rtdm_user_info_t * user_info,
				     const void *buf, size_t nbyte)
{
	int ret;

	/* write the user buffer in the kernel buffer */
	buffer.size = (nbyte > SIZE_MAX) ? SIZE_MAX : nbyte;
	ret = rtdm_safe_copy_from_user(user_info, buffer.data, buf, buffer.size);

	/* if an error has occured, send it to user */
	if (ret)
		return ret;

	/* release the semaphore */
	rtdm_sem_up(&sem);

	return nbyte;
}

/**
 * This structure describe the simple RTDM device
 *
 */
static struct rtdm_device device = {
	.struct_version = RTDM_DEVICE_STRUCT_VER,

	.device_flags = RTDM_NAMED_DEVICE,
	.context_size = 0,
	.device_name = DEVICE_NAME,

	.open_nrt = simple_rtdm_open,
	.open_rt  = simple_rtdm_open,

	.ops = {
		.close_nrt = simple_rtdm_close,
		.close_rt  = simple_rtdm_close,
		.read_rt   = simple_rtdm_read_rt,
		.write_rt  = simple_rtdm_write_rt,
	},

	.device_class = RTDM_CLASS_EXPERIMENTAL,
	.device_sub_class = SOME_SUB_CLASS,
	.profile_version = 1,
	.driver_name = "SimpleRTDM",
	.driver_version = RTDM_DRIVER_VER(0, 1, 2),
	.peripheral_name = "Simple RTDM example",
	.provider_name = "trem",
	.proc_name = device.device_name,
};

/**
 * This function is called when the module is loaded
 *
 * It simply registers the RTDM device.
 *
 */
int __init simple_rtdm_init(void)
{
	buffer.size = 0;		/* clear the buffer */
	rtdm_sem_init(&sem, 0);		/* init the global semaphore */

	return rtdm_dev_register(&device);
}

/**
 * This function is called when the module is unloaded
 *
 * It unregister the RTDM device, polling at 1000 ms for pending users.
 *
 */
void __exit simple_rtdm_exit(void)
{
	rtdm_dev_unregister(&device, 1000);
}

module_init(simple_rtdm_init);
module_exit(simple_rtdm_exit);
