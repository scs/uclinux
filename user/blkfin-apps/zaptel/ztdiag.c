#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef STANDALONE_ZAPATA
#include "zaptel.h"
#else
#include <linux/zaptel.h>
#endif

int main(int argc, char *argv[])
{
	int fd;
	int chan;
	if ((argc < 2) || (sscanf(argv[1], "%d", &chan) != 1)) {
		fprintf(stderr, "Usage: ztdiag <channel>\n");
		exit(1);
	}
	fd = open("/dev/zap/zapctl");
	if (fd < 0) {
		perror("open(/dev/zap/zapctl");
		exit(1);
	}
	if (ioctl(fd, ZT_CHANDIAG, &chan)) {
		perror("ioctl(ZT_CHANDIAG)");
		exit(1);
	}
	exit(0);
}
