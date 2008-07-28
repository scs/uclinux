/*
 * RTC driver test code
 */

#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/rtc.h>
#include <linux/ioctl.h>

int main(int argc, char *argv[])
{
	int rtc_fd;
	unsigned long data;
	int ret, i;
	struct rtc_time rtc_tm;
	char *rtc_dev = "/dev/rtc0";
	time_t t1, t2;

	if (argc > 1)
		rtc_dev = argv[1];

	printf("====== RTC Test  ====\n");
	printf("0. open and release\n");
	rtc_fd = open(rtc_dev, O_RDONLY);
	if (rtc_fd == -1) {
		printf("failed to open '%s': %s\n", rtc_dev, strerror(errno));
		exit(1);
	} else
		printf("opened '%s': fd = %d\n", rtc_dev, rtc_fd);

	printf("1. ioctl RTC_UIE_ON\n");

	ret = ioctl(rtc_fd, RTC_UIE_ON, 0);
	if (ret == -1) {
		perror("rtc ioctl RTC_UIE_ON error");
	}
	printf("2. RTC read 5 times\n");

	for( i = 1; i <6; i++){
	/* This read will block */
		ret = read(rtc_fd, &data, sizeof(data));
		if (ret == -1) {
			perror("rtc read error");
		}
		printf("RTC read %d\n", i);
	}

	printf("3. ioctl RTC_UIE_OFF\n");

	ret = ioctl(rtc_fd, RTC_UIE_OFF, 0);
	if (ret == -1) {
		perror("rtc ioctl RTC_UIE_OFF error");
	}
	printf("4. Get RTC Time\n");
	ret = ioctl(rtc_fd, RTC_RD_TIME, &rtc_tm);
	if (ret == -1) {
		perror("rtc ioctl RTC_RD_TIME error");
	}

	printf("Current RTC date/time is %d-%d-%d, %02d:%02d:%02d\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

	/* Set the RTC time/date */
	rtc_tm.tm_mday = 31;
	rtc_tm.tm_mon = 4;/* for example Sep. 8 */
	rtc_tm.tm_year = 104;
	rtc_tm.tm_hour = 2;
	rtc_tm.tm_min = 30;
	rtc_tm.tm_sec = 0;

	printf("5. Set RTC Time\n");
	ret = ioctl(rtc_fd, RTC_SET_TIME, &rtc_tm);
	if (ret == -1) {
		perror("rtc ioctl RTC_SET_TIME error");
	}

	printf("Set Current RTC date/time to %d-%d-%d, %02d:%02d:%02d\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

	printf("Get RTC time\n");
	ret = ioctl(rtc_fd, RTC_RD_TIME, &rtc_tm);
	if (ret == -1) {
		perror("rtc ioctl RTC_RD_TIME error");
	}

	printf("Current RTC date/time is %d-%d-%d, %02d:%02d:%02d\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

	rtc_tm.tm_sec += 50;
	if (rtc_tm.tm_sec >= 60) {
		rtc_tm.tm_sec %= 60;
		rtc_tm.tm_min++;
	}
	if (rtc_tm.tm_min == 60) {
		rtc_tm.tm_min = 0;
		rtc_tm.tm_hour++;
	}
	if (rtc_tm.tm_hour == 24)
		rtc_tm.tm_hour = 0;

	printf("6. Set alarm Time\n");
	ret = ioctl(rtc_fd, RTC_ALM_SET, &rtc_tm);
	if (ret == -1) {
		perror("rtc ioctl RTC_ALM_SET error");
	}

	/* Read the current alarm settings */
	printf("7. Get alarm Time\n");
	ret = ioctl(rtc_fd, RTC_ALM_READ, &rtc_tm);
	if (ret == -1) {
		perror("rtc ioctl RTC_ALM_READ error");
	}

	t1 = time(NULL);
	printf("Alarm time now set to %02d:%02d:%02d\n",
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

	/* Enable alarm interrupts */
	ret = ioctl(rtc_fd, RTC_AIE_ON, 0);
	if (ret == -1) {
		perror("rtc ioctl RTC_ALE_ON error");
	}

	printf("Waiting 50 seconds for alarm...\n");
	/* This blocks until the alarm ring causes an interrupt */
	ret = read(rtc_fd, &data, sizeof(data));
	if (ret == -1) {
		perror("rtc read error");
	}

	t2 = time(NULL);
	if (t2 - t1 < 40)
		fprintf(stderr, " Fail!  Alarm rang too fast ... took %i seconds instead of 50!\n", (int)(t2 - t1));
	else
		printf(" Okay. Alarm rang.\n");

	ret = ioctl(rtc_fd, RTC_RD_TIME, &rtc_tm);
	if (ret == -1) {
		perror("rtc ioctl RTC_RD_TIME error");
	}

	printf("Current RTC date/time is %d-%d-%d, %02d:%02d:%02d\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

	/* Disable alarm interrupts */
	printf("8. ioctl RTC_AIE_OFF\n");
	ret = ioctl(rtc_fd, RTC_AIE_OFF, 0);
	if (ret == -1) {
		perror("ioctl RTC_ALE_OFF error");
	}

	/* Robin Getz */
	printf("8.5 test sleep 10\n");
	sleep(10);
	ret = ioctl(rtc_fd, RTC_RD_TIME, &rtc_tm);
	if (ret == -1) {
		perror("rtc ioctl RTC_RD_TIME error");
	}
	printf("Current RTC date/time is %d-%d-%d, %02d:%02d:%02d\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);
	/* R Getz till here */

#if 0 /* Blackfin RTC does not support PIE */
	printf("9. ioctl RTC_PIE_ON\n");
	ret = ioctl(rtc_fd, RTC_PIE_ON, 0);
	if (ret == -1) {
		perror("ioctl RTC_PIE_ON error");
	}
	ret = ioctl(rtc_fd, RTC_RD_TIME, &rtc_tm);
	if (ret == -1) {
		perror("rtc ioctl RTC_RD_TIME error");
	}
	printf("Current RTC date/time is %d-%d-%d, %02d:%02d:%02d\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

	printf("10. ioctl RTC_IRQP_SET\n");
	ret = ioctl(rtc_fd, RTC_IRQP_SET, 1);
	if (ret == -1) {
		perror("ioctl RTC_IRQP_SET error");
	}
	ret = read(rtc_fd, &data, sizeof(data));
	if (ret == -1) {
		perror("rtc read error");
	}
	ret = ioctl(rtc_fd, RTC_RD_TIME, &rtc_tm);
	if (ret == -1) {
		perror("rtc ioctl RTC_RD_TIME error");
	}
	printf("Current RTC date/time is %d-%d-%d, %02d:%02d:%02d\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

	printf("11. ioctl RTC_PIE_OFF\n");
	ret = ioctl(rtc_fd, RTC_PIE_OFF, 0);
	if (ret == -1) {
		perror("ioctl RTC_PIE_OFF error");
	}
#endif

#if 0
	/* New RTC framework doesn't support EPOCH ioctls */
	printf("12. ioctl RTC_EPOCH_READ\n");
	ret = ioctl(rtc_fd, RTC_EPOCH_READ, &data);
	if (ret == -1) {
		perror("ioctl RTC_EPOCH_READ error");
	}
	printf("Current epoch is %ld\n", data);

	printf("13. ioctl RTC_EPOCH_SET\n");
	ret = ioctl(rtc_fd, RTC_EPOCH_SET, 2000);
	if (ret == -1) {
		perror("ioctl RTC_EPOCH_SET error");
	}
#endif
	ret = ioctl(rtc_fd, RTC_RD_TIME, &rtc_tm);
	if (ret == -1) {
		perror("rtc ioctl RTC_RD_TIME error");
	}
	printf("Current RTC date/time is %d-%d-%d, %02d:%02d:%02d\n",
		rtc_tm.tm_mday, rtc_tm.tm_mon + 1, rtc_tm.tm_year,
		rtc_tm.tm_hour, rtc_tm.tm_min, rtc_tm.tm_sec);

	printf("RTC Tests done !!\n");

	close(rtc_fd);

	return 0;
}
