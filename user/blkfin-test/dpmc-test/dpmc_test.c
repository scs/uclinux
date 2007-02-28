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
	int fd,rtc_fd,ret;
	unsigned long vco;
   	unsigned long ret1,ret2,sclk1,pllstat,cclk1,volt;
	char sclk[5];
	int choice;

	printf("##########################DPMC Test Programs##################################\n");

/*******************************Open the dpmc device ***********************************/
	fd = open("/dev/dpmc", O_RDONLY,0);
	if (fd == -1) {
		printf("/dev/dpmc open error %d\n",errno);
		exit(1);
	}
	else printf("open success fd = %d \n",fd);

	rtc_fd = open("/dev/rtc0", O_RDONLY,0);
	if (rtc_fd == -1) {
		printf("/dev/rtc0 open error %d\n",errno);
		exit(1);
		
	}
	else printf("open success fd = %d \n",rtc_fd);

/******************************Change the VCO frequency *********************************/
	printf("1. IOCTL to Change the VCO \n");
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

/******************************Change the SCLK*******************************************/
	printf("Please enter the value of sclk (Hz)\n");
	scanf("%s",sclk);
	sclk1 = atoi(sclk);
	ret = ioctl(fd, IOCTL_SET_SCLK, &sclk1);
	if (ret == -1) {
		printf("dpmc ioctl error\r\n");
		return -1;
	}
	printf("sclk was set to %u Hz \n",sclk1);

/******************************Change the CCLK*******************************************/
	printf("IOCTL to SET the CCLK \n");
	printf("Please select any of these choices for cclk (Hz)\n");
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

/********************Get the sclk ************************************************/
	printf("IOCTL to get the sclk \n");
	ret = ioctl(fd, IOCTL_GET_SYSTEMCLOCK, &sclk1);
	if (ret == -1) {
		printf("dpmc ioctl error\r\n");
		return -1;
	}
	printf("sclk got is %u Hz\n",sclk1);

/********************Get the cclk ************************************************/
	printf("IOCTL to get the cclk \n");
	ret = ioctl(fd, IOCTL_GET_CORECLOCK, &cclk1);
	if (ret == -1) {
		printf("dpmc ioctl error\r\n");
		return -1;
	}
	printf("cclk got is %u Hz\n",cclk1);

/********************************Fullon to Active Mode ********************************/	
	printf("IOCTL to CHANGE OPERATING MODE FROM FULLON TO ACTIVE \n");
	printf("Entering Active Mode \n");
	ret = ioctl(fd, IOCTL_ACTIVE_MODE, NULL);
	printf("Active mode set %d \n",ret);

/********************************Get the PLL Status***********************************/
	printf("IOCTL to get the PLL status \n");
	ret = ioctl(fd, IOCTL_GET_PLLSTATUS, &pllstat);
	printf("pll status got is 0x%x\n",pllstat);

/********************************Active Mode to Fullon Mode********************************/
	printf("IOCTL to CHANGE OPERATING MODE FROM ACTIVE TO FULLON MODE\n");
	printf("Entering Full On Mode \n");
	ret = ioctl(fd, IOCTL_FULL_ON_MODE, NULL);
	printf("Full on mode set %d \n",ret);

/********************************Get the PLL Status***********************************/
	printf("IOCTL to get the PLL status \n");
	ret = ioctl(fd, IOCTL_GET_PLLSTATUS, &pllstat);
	printf("pll status got is 0x%x\n",pllstat);

	ret = ioctl(rtc_fd, RTC_IRQP_SET, 50);
	if (ret == -1) {
		printf("ioctl RTC_IRQP_SET error\r\n");
	}

	ret = ioctl(rtc_fd, RTC_PIE_ON);
	if (ret == -1) {
		printf("ioctl RTC_PIE_ON error\r\n");
	}
	
/********************************Fullon to Sleep Mode ********************************/
	printf("IOCTL to CHANGE OPERATING MODE FROM FULLON TO SLEEP MODE\n");
	printf("Entering Sleep Mode \n");
	ret = ioctl(fd, IOCTL_SLEEP_MODE, NULL);
	printf("Out of Sleep mode set %d \n",ret);

	ret = ioctl(rtc_fd, RTC_PIE_OFF, 0);
	if (ret == -1) {
		printf("ioctl RTC_PIE_OFF error\r\n");
	}

/********************************Get the PLL Status***********************************/
	printf("IOCTL to get the PLL status \n");
	ret = ioctl(fd, IOCTL_GET_PLLSTATUS, &pllstat);
	printf("pll status got is 0x%x\n",pllstat);	

/**********************Active Mode to Sleep Mode and back to Fullon Mode**************/
	printf("IOCTL to CHANGE OPERATING MODE FROM FULLON TO ACTIVE \n");
	printf("Entering Active Mode \n");
	ret = ioctl(fd, IOCTL_ACTIVE_MODE, NULL);
	printf("Active mode set %d \n",ret);
	
/********************************Get the PLL Status***********************************/
	printf("IOCTL to get the PLL status \n");
	ret = ioctl(fd, IOCTL_GET_PLLSTATUS, &pllstat);
	printf("pll status got is 0x%x\n",pllstat);	

	ret = ioctl(rtc_fd, RTC_IRQP_SET, 50);
	if (ret == -1) {
		printf("ioctl RTC_IRQP_SET error\r\n");
	}

	ret = ioctl(rtc_fd, RTC_PIE_ON, 0);
	if (ret == -1) {
		printf("ioctl RTC_PIE_ON error\r\n");
	}
	
	printf("IOCTL to CHANGE OPERATING MODE FROM ACTIVE TO SLEEP MODE\n");
	printf("Entering Sleep Mode \n");
	ret = ioctl(fd, IOCTL_SLEEP_MODE, NULL);
	printf("Out of Sleep mode Back to active mode %d \n",ret);

	ret = ioctl(rtc_fd, RTC_PIE_OFF, 0);
	if (ret == -1) {
		printf("ioctl RTC_PIE_OFF error\r\n");
	}

	printf("IOCTL to CHANGE OPERATING MODE FROM ACTIVE TO FULLON MODE\n");
	printf("Entering Full On Mode \n");
	ret = ioctl(fd, IOCTL_FULL_ON_MODE, NULL);
	printf("Full on mode set %d \n",ret);

/********************Change the Voltage *********************************************/
	printf("IOCTL to CHANGE THE VOLTAGE \n");
	printf("Please select the voltage \r\n");
	scanf("%u",&volt);
	ret = ioctl(fd, IOCTL_CHANGE_VOLTAGE,&volt);
	if (ret == -1) {
		printf("dpmc ioctl error\r\n");
		return -1;
	}
	printf("Voltage is set to %u Hz \n",volt);
	printf("IOCTL to Change the VOLTAGE DONE!!!!! \n");

/********************Fullon Mode to Hibernate Mode *******************************/
#if 0
	printf("IOCTL to CHANGE OPERATING MODE FROM FULLON MODE TO HIBERNATE MODE\n");
	printf("Entering Hibernate Mode \n");
	ret = ioctl(fd, IOCTL_HIBERNATE_MODE, NULL);
	printf("Full on mode set %d \n",ret);

/********************Fullon Mode to DeepSleep Mode *******************************/	
	printf("IOCTL to CHANGE OPERATING MODE FROM FULLON TO Deep SLEEP MODE\n");
	printf("Entering deep Sleep Mode \n");
	ret = ioctl(fd, IOCTL_DEEP_SLEEP_MODE, NULL);
	printf("Out of deep Sleep mode set %d \n",ret);

#endif

	close(rtc_fd);
	close(fd);

	return 0;
}
