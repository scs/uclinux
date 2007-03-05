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
	unsigned long pdtim = 0x200;

	printf("##########################DPMC Test Programs##################################\n");

/*******************************Open the dpmc device ***********************************/
	fd = open("/dev/dpmc", O_RDONLY,0);
	if (fd == -1) {
		printf("/dev/dpmc open error %d\n",errno);
		exit(1);
	}
	else printf("open success fd = %d \n",fd);

	ret = ioctl(fd, IOCTL_UNMASK_WDOG_WAKEUP_EVENT, NULL);
	if(ret == 0)
		printf("WDOG event unmask success\n");

	printf("IOCTL to clear the WDOG wakeup event \n");

	printf("IOCTL to disable the WDOG timer \n");
	ret = ioctl(fd, IOCTL_DISABLE_WDOG_TIMER, NULL);
	if(ret == 0)
		printf("WDOG disabled \n");

	printf("IOCTL to program the WDOG timer \n");
	ret = ioctl(fd, IOCTL_PROGRAM_WDOG_TIMER, &pdtim);
	if(ret == 0)
		printf("WDOG programming success \n");

	printf("IOCTL to unmask the WDOG timer \n");
	
	ret = ioctl(fd, IOCTL_CLEAR_WDOG_WAKEUP_EVENT, NULL);
	if(ret == 0)
		printf("WDOG timer wakeup event cleared \n");
	else
		printf("WDOG timer wakeup event clear error \n");

	close(fd);

	return 0;
}
