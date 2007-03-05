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

	printf("IOCTL to CHANGE OPERATING MODE FROM ACTIVE TO FULLON MODE\n");

/*******************************Open the dpmc device ***********************************/
	fd = open("/dev/dpmc", O_RDONLY,0);
	if (fd == -1) {
		printf("/dev/dpmc open error %d\n",errno);
		exit(1);
	}
	else printf("open success fd = %d \n",fd);

/********************************Get the PLL Status***********************************/
	printf("IOCTL to get the PLL status \n");
	ret = ioctl(fd, IOCTL_GET_PLLSTATUS, &pllstat);
	printf("pll status got is 0x%x\n",pllstat);	

	printf("Entering Full On Mode \n");
	ret = ioctl(fd, IOCTL_FULL_ON_MODE, NULL);
	printf("Full on mode set %d \n",ret);
	
	printf("IOCTL to get the PLL status \n");
	ret = ioctl(fd, IOCTL_GET_PLLSTATUS, &pllstat);
	printf("pll status got is 0x%x\n",pllstat);	

	close(fd);

	return 0;
}
