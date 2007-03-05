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
   	unsigned long volt;

	printf("IOCTL to change voltage \n");

/*******************************Open the dpmc device ***********************************/
	fd = open("/dev/dpmc", O_RDONLY,0);
	if (fd == -1) {
		printf("/dev/dpmc open error %d\n",errno);
		exit(1);
	}
	else printf("open success fd = %d \n",fd);

/********************Change the Voltage *********************************************/
	printf("Please select the voltage \r\n");
	scanf("%u",&volt);
	ret = ioctl(fd, IOCTL_CHANGE_VOLTAGE,&volt);
	if (ret == -1) {
		printf("dpmc ioctl error\r\n");
		return -1;
	}
	printf("Voltage is set to %u mvolt \n",volt);
	printf("IOCTL to Change the VOLTAGE DONE!!!!! \n");

	close(fd);

	return 0;
}
