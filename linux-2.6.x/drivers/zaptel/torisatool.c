/*
 * BSD Telephony Of Mexico "Tormenta" card LINUX driver, version 1.8 4/8/01
 * 
 * Working with the "Tormenta ISA" Card 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. 
 *
 * Modified from original tor.c by Mark Spencer <markster@linux-support.net>
 *                     original by Jim Dixon <jim@lambdatel.com>
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include "zaptel.h"
#include "torisa.h"

static void usage(void)
{
	fprintf(stderr, "Usage: torisatool <dev> showerrors\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	int fd;
	struct torisa_debug td;
	int res;
	if (argc < 3) 
		usage();
	
	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Unable to open %s: %s\n", argv[1], strerror(errno));
		exit(1);
	}
	if (!strcasecmp(argv[2], "showerrors")) {
		res = ioctl(fd, TORISA_GETDEBUG, &td);
		if (res) {
			fprintf(stderr, "IOCTL failed: %s\n", strerror(errno));
			exit(1);
		}
		printf("Recorded misses: %u\n", td.txerrors);
		printf("IRQ execs: %u\n", td.irqcount);
		printf("Tasklet Schedules: %u\n", td.taskletsched);
		printf("Tasklets Run: %u\n", td.taskletrun);
		printf("Tasklets Executed: %u\n", td.taskletexec);
	} else 
		usage();
	exit(0);
}
