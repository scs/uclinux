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
 * This is an example that shows how RTDM devices can be used
 * with a user space program.
 *
 * The device tut01-skeleton-drv01 stores data that you write into.
 * When you read from this device, previously stored data is returned,
 * and the internal buffer is erased.
 *
 * This program does the following:
 *  1. open the device (with rt_dev_open)
 *  2. read from the device (with rt_dev_read), so previous data is deleted
 *  3. write "HelloWorld!" in the device (with rt_dev_write)
 *  4. read from the device (with rt_dev_read), it should be "HelloWorld!"
 *  5. read again from the device to check that it contains no data
 *     (deleted on last read)
 *  6. close the device (with rt_dev_close)
 *
 * To test this application, you just need to:
 *
 * $ export LD_LIBRARY_PATH=<path of xenomai>/lib
 * $ insmod tut01-skeleton-drv.ko
 * $ ./tut01-skeleton-app
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <rtdm/rtdm.h>

#define DEVICE_NAME		"tut01-skeleton-drv01"

int main(int argc, char *argv)
{
	char buf[1024];
	ssize_t size;
	int device;
	int ret;

	/* open the device */
	device = rt_dev_open(DEVICE_NAME, 0);
	if (device < 0) {
		printf("ERROR : can't open device %s (%s)\n",
		       DEVICE_NAME, strerror(-device));
		fflush(stdout);
		exit(1);
	}

	/* first read */
	size = rt_dev_read (device, (void *)buf, 1024);
	printf("Read in device %s\t: %d bytes\n", DEVICE_NAME, size);

	/* first write */
	sprintf(buf, "HelloWorld!");
	size = rt_dev_write (device, (const void *)buf, strlen(buf) + 1);
	printf("Write from device %s\t: %d bytes\n", DEVICE_NAME, size);

	/* second read */
	size = rt_dev_read (device, (void *)buf, 1024);
	printf("Read in device %s\t: %s\n", DEVICE_NAME, buf);

	/* third read */
	size = rt_dev_read (device, (void *)buf, 1024);
	printf("Read in device %s\t: %d bytes\n", DEVICE_NAME, size);

	/* close the device */
	ret = rt_dev_close(device);
	if (ret < 0) {
		printf("ERROR : can't close device %s (%s)\n",
		       DEVICE_NAME, strerror(-ret));
		fflush(stdout);
		exit(1);
	}

	return 0;
}
