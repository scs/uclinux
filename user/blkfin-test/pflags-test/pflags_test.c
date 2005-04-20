/*
 * PFLAGS driver test code
 */

#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <errno.h>
#include <unistd.h> 
#include "pflags.h"


int main()
{
	int fd0,fd1,ret;
	char data_read[2];

	printf("########################## PFLAGS TEST ###############################\n");
	
	fd0 = open("/dev/pf2", O_RDWR,0);
	if (fd0 == -1) {
		printf("/dev/PF2 open error %d\n",errno);
		exit(1);
	}
	else printf("open success /dev/pf2 \n");

	fd1 = open("/dev/pf5", O_RDWR,0);
	if (fd1 == -1) {
		printf("/dev/PF5 open error %d\n",errno);
		exit(1);
	}
	else printf("open success /dev/pf5 \n");


	ret = ioctl(fd0, SET_FIO_DIR, OUTPUT);

	ret = ioctl(fd1, SET_FIO_DIR, INPUT);	
	ret = ioctl(fd1, SET_FIO_INEN, INPUT_ENABLE);
		
	ret= 0;

	printf("\n\nPress BTN1 to EXIT\n");

  while(!ret) 
  {
		write(fd0,"0",sizeof("0")); 
		usleep(100);
		write(fd0,"1",sizeof("1"));
		usleep(100);

		read(fd1,data_read,2);
		if(data_read[0] == '1') 
		  ret=1;
  }

	close(fd1);
	close(fd0);

	exit(0);
}
