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
 * This kernel driver demonstrates how an RTDM device can be set up.
 *
 * It is a simple device, only 4 operation are provided:
 *  - open:  start device usage
 *  - close: ends device usage
 *  - write: store transfered data in an internal buffer
 *  - read:  return previously stored data and erase buffer
 *
 */

#include <linux/module.h>
#include <rtdm/rtdm_driver.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("trem");

#define SIZE_MAX		1024
#define DEVICE_NAME		"tut01-skeleton-drv01"
#define SOME_SUB_CLASS		4711

/**
 * The context of a device instance
 *
 * A context is created each time a device is opened and passed to
 * other device handlers when they are called.
 *
 */
typedef struct buffer_s {
	int size;
	char data[SIZE_MAX];
} buffer_t;

/**
 * Open the device
 *
 * This function is called when the device shall be opened.
 *
 */
static int simple_rtdm_open_nrt(struct rtdm_dev_context *context,
				rtdm_user_info_t * user_info, int oflags)
{
	buffer_t * buffer = (buffer_t *) context->dev_private;
	buffer->size = 0; /* clear the buffer */

	return 0;
}

/**
 * Close the device
 *
 * This function is called when the device shall be closed.
 *
 */
static int simple_rtdm_close_nrt(struct rtdm_dev_context *context,
				 rtdm_user_info_t * user_info)
{
	return 0;
}

/**
 * Read from the device
 *
 * This function is called when the device is read in non-realtime context.
 *
 */
static ssize_t simple_rtdm_read_nrt(struct rtdm_dev_context *context,
				    rtdm_user_info_t * user_info, void *buf,
				    size_t nbyte)
{
	buffer_t * buffer = (buffer_t *) context->dev_private;
	int size = (buffer->size > nbyte) ? nbyte : buffer->size;

	buffer->size = 0;
	if (rtdm_safe_copy_to_user(user_info, buf, buffer->data, size))
		rtdm_printk("ERROR : can't copy data from driver\n");

	return size;
}

/**
 * Write in the device
 *
 * This function is called when the device is written in non-realtime context.
 *
 */
static ssize_t simple_rtdm_write_nrt(struct rtdm_dev_context *context,
				     rtdm_user_info_t * user_info,
				     const void *buf, size_t nbyte)
{
	buffer_t * buffer = (buffer_t *) context->dev_private;

	buffer->size = (nbyte > SIZE_MAX) ? SIZE_MAX : nbyte;
	if (rtdm_safe_copy_from_user(user_info, buffer->data, buf, buffer->size))
		rtdm_printk("ERROR : can't copy data to driver\n");

	return nbyte;
}

/**
 * This structure describe the simple RTDM device
 *
 */
static struct rtdm_device device = {
	.struct_version = RTDM_DEVICE_STRUCT_VER,

	.device_flags = RTDM_NAMED_DEVICE,
	.context_size = sizeof(buffer_t),
	.device_name = DEVICE_NAME,

	.open_nrt = simple_rtdm_open_nrt,

	.ops = {
		.close_nrt = simple_rtdm_close_nrt,
		.read_nrt = simple_rtdm_read_nrt,
		.write_nrt = simple_rtdm_write_nrt,
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
