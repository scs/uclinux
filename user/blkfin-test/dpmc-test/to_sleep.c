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
#include "blackfin_rtc.h"

int main()
{
	int fd,rtc_fd,ret;
   	unsigned long pllstat;

	printf("Entering sleep mode \n");

/*******************************Open the dpmc device ***********************************/
	fd = open("/dev/dpmc", O_RDONLY,0);
	if (fd == -1) {
		printf("/dev/dpmc open error %d\n",errno);
		exit(1);
	}

	rtc_fd = open("/dev/rtc", O_RDONLY,0);
	if (rtc_fd == -1) {
		printf("/dev/rtc open error %d\n",errno);
		exit(1);
		
	}
/********************************Get the PLL Status***********************************/
	ret = ioctl(rtc_fd, RTC_SWCNT_ON, 0);
	if (ret == -1) {
		printf("ioctl RTC_SWCNT_ON error\r\n");
	}
	
	ret = ioctl(rtc_fd, RTC_SWCNT_SET, 50);
	if (ret == -1) {
		printf("ioctl RTC_SWCNT_SET error\r\n");
	}
	
	ret = ioctl(fd, IOCTL_SLEEP_MODE, NULL);
	printf("Out of Sleep mode set %d \n",ret);

	ret = ioctl(rtc_fd, RTC_SWCNT_OFF, 0);
	if (ret == -1) {
		printf("ioctl RTC_SWCNT_ON error\r\n");
	}

/********************************Get the PLL Status***********************************/
	printf("IOCTL to get the PLL status \n");
	ret = ioctl(fd, IOCTL_GET_PLLSTATUS, &pllstat);
	printf("pll status got is 0x%x\n",pllstat);	
	
	close(rtc_fd);
	close(fd);

	return 0;
}
