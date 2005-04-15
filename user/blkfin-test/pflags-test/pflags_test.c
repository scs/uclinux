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
#include <linux/rtc.h>
#include "pflags.h"


#include <sys/poll.h>


int main()
{
	int fd0,fd1,fd2,i,ret,loop;
	char data[10]={"0111011100"};	
	char data_read[6];
	int back;
    unsigned short status;



	printf("########################## Test Programs ##################################\n");

/*******************************Open device ***********************************/
	i= 10;
	fd0 = open("/dev/pf2", O_RDWR,0);
	if (fd0 == -1) {
		printf("/dev/PF2 open error %d\n",errno);
		exit(1);
	}
	else printf("open success fd0 = %d \n",fd0);
	
	fd1 = open("/dev/pf3", O_RDWR,0);
	if (fd1 == -1) {
		printf("/dev/PF3 open error %d\n",errno);
		exit(1);
	}
	else printf("open success fd1 = %d \n",fd1);
	
	fd2 = open("/dev/pf4", O_RDWR,0);
	if (fd2 == -1) {
		printf("/dev/PF3 open error %d\n",errno);
		exit(1);
	}
	else printf("open success fd2 = %d \n",fd2);


/******************************Change the Direction *********************************/

	ret = ioctl(fd0, SET_FIO_DIR,OUTPUT);
	if (ret == -1) {
		printf("plags ioctl error\r\n");
		return -1;
	}

	ret = ioctl(fd1, SET_FIO_DIR,OUTPUT);
	if (ret == -1) {
		printf("plags ioctl error\r\n");
		return -1;
	}
	
	ret = ioctl(fd2, SET_FIO_DIR,OUTPUT);
	if (ret == -1) {
		printf("plags ioctl error\r\n");
		return -1;
	}


	printf("########################## Write Test ##################################\n");

for(loop=0; loop<4 ;loop++) {
	for(i=0;i<3;i++) {
		write(fd0,data+i,sizeof(data));
		write(fd1,data+i+3,sizeof(data));
		write(fd2,data+i+6,sizeof(data));
		sleep(1);
	}
}



	close(fd0);
	close(fd1);
	close(fd2);

	return 0;
}
