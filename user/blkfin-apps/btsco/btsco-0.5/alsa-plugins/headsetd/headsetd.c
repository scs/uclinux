/*
 *
 *  Headset Profile support for Linux
 *
 *  Copyright (C) 2006  Fabien Chevalier
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <config.h>

#include "daemon.h"
#include "sockets.h"

static void usage(void)
{
	printf("headsetd - Bluetooth headset daemon version %s\n", VERSION);
	printf("Usage: \n");
	printf("\theadsetd [-n not_daemon]\n");
}

int main(int argc, char **argv)
{
	int opt;
	struct Daemon daemon;
	int daemonize = 1;

	while ((opt = getopt(argc, argv, "n")) != EOF) {
		switch (opt) {
		case 'n':
			daemonize = 0;
			break;

		default:
			usage();
			exit(1);
		}
	}

	if (daemonize) {
		int ret = fork();
		if (ret > 0) {
			exit(0);
		}
		else if(ret < 0) {
			perror("Unable to fork");
			exit(1);
		}
		else {
			int fd;
			/* Direct stdin,stdout,stderr to '/dev/null' */
			fd = open("/dev/null", O_RDWR);
			dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
			close(fd);
	
			setsid();
	
			chdir("/");
		}
	}

	umask(0077);

	int ret = createDaemon(&daemon);

	if(ret != 0) {
		return ret;
	}

	daemon_enterLoop(&daemon);

	daemon_destroy(&daemon);

	return 0;
}

int hspd_sockets[DAEMON_NUM_SOCKS];
