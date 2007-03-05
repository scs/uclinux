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
   	unsigned long pllstat;

	printf("IOCTL to CHANGE OPERATING MODE FROM FULLON TO ACTIVE \n");

/*******************************Open the dpmc device ***********************************/
	fd = open("/dev/dpmc", O_RDONLY,0);
	if (fd == -1) {
		printf("/dev/dpmc open error %d\n",errno);
		exit(1);
	}
	else printf("open success fd = %d \n",fd);

/********************************Fullon to Active Mode ********************************/	
	printf("Entering Active Mode \n");
	ret = ioctl(fd, IOCTL_ACTIVE_MODE, NULL);
	printf("Active mode set %d \n",ret);

/********************************Get the PLL Status***********************************/
	printf("IOCTL to get the PLL status \n");
	ret = ioctl(fd, IOCTL_GET_PLLSTATUS, &pllstat);
	printf("pll status got is 0x%x\n",pllstat);

	close(fd);

	return 0;
}
