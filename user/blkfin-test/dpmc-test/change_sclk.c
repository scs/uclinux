/*
 * RTC driver test code
 */

#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <errno.h>
#include "dpmc.h"
#include <linux/rtc.h>

int main()
{
	int fd,ret;
   	unsigned long sclk1;
	char sclk[5];
	
	printf("IOCTL to change sclk \n");
	
/*******************************Open the dpmc device ***********************************/
	fd = open("/dev/dpmc", O_RDONLY,0);
	if (fd == -1) {
		printf("/dev/dpmc open error %d\n",errno);
		exit(1);
	}
	else printf("open success fd = %d \n",fd);

/******************************Change the SCLK*******************************************/
	printf("Please enter the value of sclk \n");
	scanf("%s",sclk);
	sclk1 = atoi(sclk);
	ret = ioctl(fd, IOCTL_SET_SCLK, &sclk1);
	if (ret == -1) {
		printf("dpmc ioctl error\r\n");
		return -1;
	}
	printf("sclk was set to %u Hz \n",sclk1);

/********************Get the sclk ************************************************/
	printf("IOCTL to get the sclk \n");
	ret = ioctl(fd, IOCTL_GET_SYSTEMCLOCK, &sclk1);
	if (ret == -1) {
		printf("dpmc ioctl error\r\n");
		return -1;
	}
	printf("sclk got is %u Hz\n",sclk1);

	close(fd);

	return 0;
}
