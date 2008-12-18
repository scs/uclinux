/*
 * File:         iwrap_boot.c
 * Author:       Michael Hennerich
 * Description:  Bluegiga iWarp boot mode utility
 *
 *               Copyright 2008 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * Licensed under the GPL-2 or later.
 * http://www.gnu.org/licenses/gpl.txt
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <termios.h>

#define VERSION         "0.1"

void usage(FILE * fp, int rc)
{
	fprintf(fp,
		"Usage: iwrap_boot [-?vbhu] serial-device\n");
	fprintf(fp, "        -b             Serial BCSP HCI\n");
	fprintf(fp, "        -h             Serial H4 HCI\n");
	fprintf(fp, "        -u             USB HCI\n");
	fprintf(fp, "        -h?            this help\n");
	fprintf(fp, "        -v             print version info\n");
	exit(rc);
}

int main(int argc, char* argv[])
{
	struct termios ti;
 	int fd, ret, c, mode = -1;
	char str[8];

	while ((c = getopt(argc, argv, "v?hbu")) > 0) {
		switch (c) {
		case 'v':
			printf("%s: version %s\n", argv[0], VERSION);
			exit(0);
		case 'h':
			mode = 4;
			break;
		case 'b':
			mode = 1;
			break;
		case 'u':
			mode = 3;
			break;
		case '?':
			usage(stdout, 0);
			break;
		default:
			fprintf(stderr, "ERROR: unkown option '%c'\n", c);
			usage(stderr, 1);
			break;
		}
	}

	if (mode < 0)
		mode = 1;

	sprintf(str, "boot %i\n", mode);
	sleep(1); /* Wait some time to make sure the BT module is booted */

	fd = open(argv[optind], O_RDWR | O_NOCTTY);
	if (fd < 0) {
		fprintf(stderr, "Can't open serial port: %s (%d)\n",
						strerror(errno), errno);
		return -1;
	}

	tcflush(fd, TCIOFLUSH);

	if (tcgetattr(fd, &ti) < 0) {
		fprintf(stderr, "Can't get port settings: %s (%d)\n",
						strerror(errno), errno);
		close(fd);
		return -1;
	}

	cfmakeraw(&ti);

	ti.c_cflag |=  CLOCAL;
	ti.c_cflag &= ~CRTSCTS;
	ti.c_cflag &= ~PARENB;
	ti.c_cflag &= ~PARODD;
	ti.c_cflag &= ~CSIZE;
	ti.c_cflag |=  CS8;
	ti.c_cflag &= ~CSTOPB;

	ti.c_cc[VMIN] = 1;
	ti.c_cc[VTIME] = 0;

	cfsetospeed(&ti, B115200);

	if (tcsetattr(fd, TCSANOW, &ti) < 0) {
		fprintf(stderr, "Can't change port settings: %s (%d)\n",
						strerror(errno), errno);
		close(fd);
		return -1;
	}

	tcflush(fd, TCIOFLUSH);

	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
		fprintf(stderr, "Can't set non blocking mode: %s (%d)\n",
						strerror(errno), errno);
		close(fd);
		return -1;
	}

	ret = write(fd, str, sizeof(str));

	if (ret < 0)
		fprintf(stderr, "UART write error\n");
	else
		ret = 0;

	tcflush(fd, TCIOFLUSH);
	close(fd);
	sleep(1);	/* Wait some time to make sure the BT module is booted */

	return ret;
}
