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
 * This is an example that shows how blocking RTDM devices can be used
 * with a user space program in realtime context.
 *
 * The device tut02-skeleton-drv01 stores data that you write into.
 * When you read from this device, previously stored data is returned,
 * and the internal buffer is erased. If you try to read more than you have
 * written, the reader is blocked until the next write took place.
 *
 * This program does the following:
 * - If you give an argument to the command line, this argument is written
 *   in the device (with rt_dev_write)
 * - If you don't give an argument to the command line, the progam read
 *   in the device (with rt_dev_read).
 *
 * To test this application, you just need to:
 *
 * $ export LD_LIBRARY_PATH=<path of xenomai>/lib
 * $ insmod tut02-skeleton-drv.ko
 * $ ./tut02-skeleton-app "Hello Master"
 * $ ./tut02-skeleton-app
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>	/* for MCL_CURRENT and MCL_FUTURE */
#include <rtdm/rtdm.h>
#include <native/task.h>

#define DEVICE_NAME		"tut02-skeleton-drv01"

RT_TASK rt_task_desc;

int main(int argc, char *argv[])
{
	char buf[1024];
	ssize_t size;
	int device;
	int ret;

	/* no memory-swapping for this programm */
	ret = mlockall(MCL_CURRENT | MCL_FUTURE);
	if (ret) {
		perror("ERROR : mlockall has failled");
		exit(1);
	}

	/*
	 * Turn the current task into a RT-task.
	 * The task has no name to allow multiple program instances to be run
	 * at the same time.
	 */
	ret = rt_task_shadow(&rt_task_desc, NULL, 1, 0);
	if (ret)
	{
		fprintf(stderr, "ERROR : rt_task_shadow: %s\n",
			strerror(-ret));
		exit(1);
	}

	/* open the device */
	device = rt_dev_open(DEVICE_NAME, 0);
	if (device < 0) {
		printf("ERROR : can't open device %s (%s)\n",
		       DEVICE_NAME, strerror(-device));
		exit(1);
	}

	/*
	 * If an argument was given on the command line, write it to the device,
	 * otherwise, read from the device.
	 */
	if (argc == 2)
	{
		sprintf(buf, "%s", argv[1]);
		size = rt_dev_write (device, (const void *)buf, strlen(buf) + 1);
		printf("Write from device %s\t: %d bytes\n", DEVICE_NAME, size);
	} else {
		size = rt_dev_read (device, (void *)buf, 1024);
		printf("Read in device %s\t: %s\n", DEVICE_NAME, buf);
	}

	/* close the device */
	ret = rt_dev_close(device);
	if (ret < 0) {
		printf("ERROR : can't close device %s (%s)\n",
		       DEVICE_NAME, strerror(-ret));
		exit(1);
	}

	return 0;
}
