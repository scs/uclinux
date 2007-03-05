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
   	unsigned long ret1,ret2,cclk1;
	int choice;

	printf("IOCTL to SET the CCLK \n");

/*******************************Open the dpmc device ***********************************/
	fd = open("/dev/dpmc", O_RDONLY,0);
	if (fd == -1) {
		printf("/dev/dpmc open error %d\n",errno);
		exit(1);
	}
	else printf("open success fd = %d \n",fd);

/******************************Get the VCO at which the processor is running ***********/
	printf("IOCTL to GET the vco \n");
	ret = ioctl(fd, IOCTL_GET_VCO, &ret1);
	if (ret == -1) {
		printf("dpmc ioctl error\r\n");
		return -1;
	}
	printf("vco set is %u Hz\n",ret1);

/******************************Change the CCLK*******************************************/
	printf("Please select any of these choices for cclk \n");
	printf("1. %u \t 2. %u \t 3. %u \t 4. %u \n",ret1,ret1/2,ret1/4,ret1/8);
	scanf("%d",&choice);
	if(choice == 1)	ret2 = ret1;
	else if(choice == 2)	ret2 = ret1/2;
	else if(choice == 3)	ret2 = ret1/4;
	else if(choice == 4)	ret2 = ret1/8;
	ret = ioctl(fd, IOCTL_SET_CCLK, &ret2);
	if (ret == -1) {
		printf("dpmc ioctl error\r\n");
		return -1;
	}
	printf("cclk was set to %u Hz \n",ret2);

/********************Get the cclk ************************************************/
	printf("IOCTL to get the cclk \n");
	ret = ioctl(fd, IOCTL_GET_CORECLOCK, &cclk1);
	if (ret == -1) {
		printf("dpmc ioctl error\r\n");
		return -1;
	}
	printf("cclk got is %u Hz\n",cclk1);

	close(fd);

	return 0;
}
