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

#include "dpmc.h"

void main()
{
	int fd;
	unsigned long data,vco;
   	unsigned long ret,ret1,ret2,ret3,i,sclk1;
	char sclk[5],cclk[5];
	int choice;

	printf("====== DPMC Test ======\n");
	printf("0. open and release\n");
	fd = open("/dev/dpmc", O_RDONLY,0);
	if (fd == -1) {
		printf("/dev/dpmc open error\n");
		exit(1);		
	}

	else printf("open success fd = %d \n",fd);


	printf("IOCTL to SET the vco \n");
	printf("Please select the VCO \r\n");
	scanf("%d",&vco);	
	ret = ioctl(fd, IOCTL_CHANGE_FREQUENCY,&vco);
	if (ret == -1) {
		printf("dpmc ioctl error\r\n");
	}
	printf("VCO is set to %u MHz \n",vco);

	
	printf("IOCTL to GET the vco \n");
	ret = ioctl(fd, IOCTL_GET_VCO, &ret1);
	printf("vco set is %u MHz\n",ret1);

	printf("IOCTL to SET the CCLK \n");
	printf("Please select any of these choices for cclk \n");
	printf("1. %u \t 2. %u \t 3. %u \t 4. %u \n",ret1,ret1/2,ret1/4,ret1/8);
	scanf("%d",&choice);
	if(choice == 1)	ret2 = ret1;
	else if(choice == 2)	ret2 = ret1/2;
	else if(choice == 3)	ret2 = ret1/4;
	else if(choice == 4)	ret2 = ret1/8;
	ret = ioctl(fd, IOCTL_SET_CCLK, &ret2);
	printf("cclk was set to %u MHz \n",ret2);
	
	for(i=0;i<1000;i++);

	printf("IOCTL to CHANGE OPERATING MODE FROM FULLON TO ACTIVE \n");
	printf("Entering Active Mode \n");
	ret = ioctl(fd, IOCTL_ACTIVE_MODE, NULL);
	printf("Active mode set %d \n",ret);


	for(i=0;i<1000;i++);	
	
	printf("IOCTL to CHANGE OPERATING MODE FROM ACTIVE TO FULLON MODE\n");
	printf("Entering Full On Mode \n");
	ret = ioctl(fd, IOCTL_FULL_ON_MODE, NULL);
	printf("Full on mode set %d \n",ret);

	for(i=0;i<10000000;i++);
#if 0

	printf("IOCTL to CHANGE OPERATING MODE FROM FULLON TO SLEEP MODE\n");
	printf("Entering Sleep Mode \n");
	ret = ioctl(fd, IOCTL_SLEEP_MODE, NULL);
	printf("Out of Sleep mode set %d \n",ret);

	printf("IOCTL to CHANGE OPERATING MODE FROM SLEEP TO FULLON MODE\n");
	printf("Entering Full On Mode \n");
	ret = ioctl(fd, IOCTL_FULL_ON_MODE, NULL);
	printf("Full on mode set %d \n",ret);

	
	for(i=0;i<10000000;i++);	

	printf("IOCTL to CHANGE OPERATING MODE FROM FULLON TO SLEEP MODE\n");
	printf("Entering Full On Mode \n");
	ret = ioctl(fd, IOCTL_DEEP_SLEEP_MODE, NULL);
	printf("Out of Deep Sleep mode set %d \n",ret);
	
	for(i=0;i<10000000;i++);

	printf("IOCTL to CHANGE OPERATING MODE FROM SLEEP TO FULLON MODE\n");
	printf("Entering Full On Mode \n");
	ret = ioctl(fd, IOCTL_FULL_ON_MODE, NULL);
	printf("Full on mode set %d \n",ret);
	
	for(i=0;i<10000000;i++);

	printf("Please enter the value of sclk \n");
	scanf("%s",sclk);
	sclk1 = atoi(sclk);
	ret3 = ioctl(fd, IOCTL_SET_SCLK, &sclk1);
	printf("sclk was set to %u MHz \n",sclk1);

	printf("IOCTL to get the sclk \n");
	ret = ioctl(fd, IOCTL_GET_SYSTEMCLOCK, NULL);
	printf("sclk got is %d MHz\n",ret);

	printf("IOCTL to get the cclk \n");
	ret = ioctl(fd, IOCTL_GET_CORECLOCK, NULL);
	printf("cclk got is %d MHz\n",ret);

	printf("IOCTL to get the PLL status \n");
	ret = ioctl(fd, IOCTL_GET_PLLSTATUS, NULL);
	printf("pll status got is %d MHz\n",ret);
#endif
	close(fd);
}
