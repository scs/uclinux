/*
 * RTC driver test code
 */

#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/rtc.h>
#include <linux/ioctl.h>

#include "dpmc.h"

void main()
{
	int fd;
	unsigned long data;
   	int ret, i;

	printf("====== DPMC Test ======\n");
	printf("0. open and release\n");
	fd = open("/dev/dpmc", O_RDONLY,0);
	if (fd == -1) {
		printf("/dev/dpmc open error\n");
		exit(1);		
	}

	else printf("open success fd = %d \n",fd);

	printf("1. ioctl CHANGE FREQ \r\n");

	ret = ioctl(fd, IOCTL_CHANGE_FREQUENCY,420);
	if (ret == -1) {
		printf("dpmc ioctl error\r\n");
	}

#if 0

	for( i = 1; i <6; i++){
	/* This read will block */
		ret = read(rtc_fd, &data, sizeof(unsigned long));
		if (ret == -1) {
			printf("rtc read error\r\n");
		}
		printf("RTC read %d\r\n", i);
	}

	printf("3. ioctl RTC_UIE_OFF\r\n");

	ret = ioctl(rtc_fd, RTC_UIE_OFF, 0);
	if (ret == -1) {
		printf("rtc ioctl RTC_UIE_OFF error\r\n");
	}
	printf("4. Get RTC Time\r\n");
	ret = ioctl(rtc_fd, RTC_RD_TIME, &rtc_tm);
	if (ret == -1) {
		printf("rtc ioctl RTC_RD_TIME error\r\n");
	}
	
	printf("Current RTC date/time is %d-%d-%d, %02d:%02d:%02d.\r\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

	/* Set the RTC time/date */
	rtc_tm.tm_mday = 31;
	rtc_tm.tm_mon = 4;/* for example Sep. 8 */
	rtc_tm.tm_year = 104;
	rtc_tm.tm_hour = 2;
	rtc_tm.tm_min = 30;
	rtc_tm.tm_sec = 0;
	
	printf("5. Set RTC Time\r\n");
	ret = ioctl(rtc_fd, RTC_SET_TIME, &rtc_tm);
	if (ret == -1) {
		printf("rtc ioctl RTC_SET_TIME error\r\n");
	}
	
	printf("Set Current RTC date/time to %d-%d-%d, %02d:%02d:%02d.\r\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);
	
	printf("Get RTC time\r\n");
	ret = ioctl(rtc_fd, RTC_RD_TIME, &rtc_tm);
	if (ret == -1) {
		printf("rtc ioctl RTC_RD_TIME error\r\n");
	}
	
	printf("Current RTC date/time is %d-%d-%d, %02d:%02d:%02d.\r\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

	rtc_tm.tm_sec += 50;
	if (rtc_tm.tm_sec >= 60) {
		rtc_tm.tm_sec %= 60;
		rtc_tm.tm_min++;
	}
	if  (rtc_tm.tm_min == 60) {
		rtc_tm.tm_min = 0;
		rtc_tm.tm_hour++;
	}
	if  (rtc_tm.tm_hour == 24)
		rtc_tm.tm_hour = 0;
	
	printf("6. Set alarm Time\r\n");
	ret = ioctl(rtc_fd, RTC_ALM_SET, &rtc_tm);
	if (ret == -1) {
		printf("rtc ioctl RTC_ALM_SET error\r\n");
	}
	
	/* Read the current alarm settings */
	printf("7. Get alarm Time\r\n");
	ret = ioctl(rtc_fd, RTC_ALM_READ, &rtc_tm);
	if (ret == -1) {
		printf("rtc ioctl RTC_ALM_READ error\r\n");
	}
	
	printf("Alarm time now set to %02d:%02d:%02d.\r\n",
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

	
	/* Enable alarm interrupts */
	ret = ioctl(rtc_fd, RTC_AIE_ON, 0);
	if (ret == -1) {
		printf("rtc ioctl RTC_ALE_ON error\r\n");
	}
	
	printf("Waiting 50 seconds for alarm...\r\n");
	/* This blocks until the alarm ring causes an interrupt */
	ret = read(rtc_fd, &data, sizeof(unsigned long));
	if (ret == -1) {
		printf("rtc read errot\r\n");
	}
	printf(" Okay. Alarm rang.\r\n");
	
	ret = ioctl(rtc_fd, RTC_RD_TIME, &rtc_tm);
	if (ret == -1) {
		printf("rtc ioctl RTC_RD_TIME error\r\n");
	}
	
	printf("Current RTC date/time is %d-%d-%d, %02d:%02d:%02d.\r\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

	/* Disable alarm interrupts */
	printf("8. ioctl RTC_AIE_OFF\r\n");
	ret = ioctl(rtc_fd, RTC_AIE_OFF, 0);
	if (ret == -1) {
		printf("ioctl RTC_ALE_OFF error\r\n");
	}

	printf("9. ioctl RTC_SWCNT_ON\r\n");
	ret = ioctl(rtc_fd, RTC_SWCNT_ON, 0);
	if (ret == -1) {
		printf("ioctl RTC_SWCNT_ON error\r\n");
	}
	ret = ioctl(rtc_fd, RTC_RD_TIME, &rtc_tm);
	if (ret == -1) {
		printf("rtc ioctl RTC_RD_TIME error\r\n");
	}
	printf("Current RTC date/time is %d-%d-%d, %02d:%02d:%02d.\r\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

	printf("10. ioctl RTC_SWCNT_SET\r\n");
	ret = ioctl(rtc_fd, RTC_SWCNT_SET, 1);
	if (ret == -1) {
		printf("ioctl RTC_SWCNT_SET error\r\n");
	}
	ret = read(rtc_fd, &data, sizeof(unsigned long));
	if (ret == -1) {
		printf("rtc read errot\r\n");
	}
	ret = ioctl(rtc_fd, RTC_RD_TIME, &rtc_tm);
	if (ret == -1) {
		printf("rtc ioctl RTC_RD_TIME error\r\n");
	}
	printf("Current RTC date/time is %d-%d-%d, %02d:%02d:%02d.\r\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

	printf("11. ioctl RTC_SWCNT_OFF\r\n");
	ret = ioctl(rtc_fd, RTC_SWCNT_OFF, 0);
	if (ret == -1) {
		printf("ioctl RTC_SWCNT_OFF error\r\n");
	}

	printf("12. ioctl RTC_EPOCH_READ\r\n");
	ret = ioctl(rtc_fd, RTC_EPOCH_READ, &data);
	if (ret == -1) {
		printf("ioctl RTC_EPOCH_READ error\r\n");
	}
	printf("Current epoch is %ld\r\n",data);

	printf("13. ioctl RTC_EPOCH_SET\r\n");
	ret = ioctl(rtc_fd, RTC_EPOCH_SET, 2310);
	if (ret == -1) {
		printf("ioctl RTC_EPOCH_SET error\r\n");
	}
	ret = ioctl(rtc_fd, RTC_RD_TIME, &rtc_tm);
	if (ret == -1) {
		printf("rtc ioctl RTC_RD_TIME error\r\n");
	}
	printf("Current RTC date/time is %d-%d-%d, %02d:%02d:%02d.\r\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

#endif
	close(fd);
}
