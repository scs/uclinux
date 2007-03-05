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
	int fd;
	int ret;
	unsigned long vco;
   	unsigned long ret1;

	printf("IOCTL to Change the VCO \n");

/*******************************Open the dpmc device ***********************************/
	fd = open("/dev/dpmc", O_RDONLY,0);
	if (fd == -1) {
		printf("/dev/dpmc open error %d\n",errno);
		exit(1);
	}
	else printf("open success fd = %d \n",fd);

/******************************Change the VCO frequency *********************************/
	printf("Please select the VCO \r\n");
	scanf("%u",&vco);
	ret = ioctl(fd, IOCTL_CHANGE_FREQUENCY,&vco);
	if (ret == -1) {
		printf("dpmc ioctl error\r\n");
		return -1;
	}
	printf("VCO is set to %u Hz \n",vco);
	printf("IOCTL to Change the VCO DONE!!!!! \n");

/******************************Get the VCO at which the processor is running ***********/
	printf("IOCTL to GET the vco \n");
	ret = ioctl(fd, IOCTL_GET_VCO, &ret1);
	if (ret == -1) {
		printf("dpmc ioctl error\r\n");
		return -1;
	}
	printf("vco set is %u Hz\n",ret1);

	close(fd);

	return 0;
}
