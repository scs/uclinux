/* File:   ad5304_test.c
 * Desc:   Simple test for the AD5304 driver
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <linux/ad5304.h>

int main(int argc, char *argv[])
{
	int fd, ret, val;
	const char *dev;

	if (argc <= 1) {
		printf("Usage: %s <value> [device]\n", argv[0]);
		return 1;
	}

	if (sscanf(argv[1], "%i", &val) != 1) {
		printf("Invalid value '%s'\n", argv[1]);
		return 1;
	}

	dev = (argc > 2 ? argv[2] : "/dev/ad5304_spi2");

	printf("Writing '0x%X' to '%s'\n", val, dev);

	fd = open(dev, O_RDONLY);
	if (fd < 0) {
		perror("Could not open");
		return 1;
	}

	ret = ioctl(fd, AD5304_SET_DAC, val);
	printf("ioctl() returned %i\n", ret);

	close(fd);

	return 0;
}
