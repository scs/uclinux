
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <strings.h>
#include <math.h>

#define PPI_DEVICE      "/dev/ppi"
#define VERSION         "0.1"

int write_dac(unsigned short *buffer, unsigned short cnt)
{

	int fd;

	/* Open /dev/ppi */
	fd = open(PPI_DEVICE, O_RDWR, 0);
	if (fd < 1) {
		printf("Could not open dev ppi : %d \n", errno);
		return fd;
	}

	write(fd, buffer, cnt * 2);
	close(fd);

	return 0;
}

int read_adc(unsigned short *buffer, unsigned short cnt)
{
	int fd;

	/* Open /dev/ppi */
	fd = open(PPI_DEVICE, O_RDWR, 0);
	if (fd < 1) {
		printf("Could not open dev ppi : %d \n", errno);
		return fd;
	}

	read(fd, buffer, cnt * 2);
	close(fd);

	return 0;
}
