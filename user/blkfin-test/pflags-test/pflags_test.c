/*
 *
 *    Rev:          $Id: pflags_test.c 5104 2007-03-22 10:21:38Z sonicz $
 *    Revision:     $Revision: 5104 $
 *    Source:       $Source$  
 *    Created:      Do Apr 21 11:02:09 CEST 2005
 *    Author:       Michael Hennerich
 *    mail:         hennerich@blackfin.uclinux.org
 *    Description:  PFLAGS driver test code  
 *                  
 *   Copyright (C) 2005 Michael Hennerich
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 ****************************************************************************
 * MODIFICATION HISTORY:
 ***************************************************************************/

#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <errno.h>
#include <unistd.h> 
#include <string.h>
#include "pflags.h"

int main(int argc, char *argv[])
{
	int fd0,fd1,ret;
	char data_read[2];
	char led[10], button[10];

	if(argc<2) {
		printf("usage: pflag_test < bf533 | bf537>\n");
		return 0;
	}
	
	if(strncmp(argv[1], "bf537", 6)==0) {
		strcpy(led, "/dev/pf6");
		strcpy(button, "/dev/pf2");
		printf("bf537\n");
	}
	else {
		strcpy(led, "/dev/pf2");
		strcpy(button, "/dev/pf5");
	}
	
	printf("########################## PFLAGS TEST ###############################\n");
	
	fd0 = open(led, O_RDWR,0);
	if (fd0 == -1) {
		printf("%s open error %d\n", led, errno);
		exit(1);
	}
	else printf("open success %s \n", led);

	fd1 = open(button, O_RDWR,0);
	if (fd1 == -1) {
		printf("%s open error %d\n", button, errno);
		exit(1);
	}
	else printf("open success %s \n", button);


	ret = ioctl(fd0, SET_FIO_DIR, OUTPUT);
	ret = ioctl(fd0, SET_FIO_INEN, INPUT_DISABLE);

	ret = ioctl(fd1, SET_FIO_DIR, INPUT);	
	ret = ioctl(fd1, SET_FIO_INEN, INPUT_ENABLE);
	if(strncmp(argv[1], "bf533", 6)==0) 
		ret = ioctl(fd1, SET_FIO_POLAR, ACTIVELOW_FALLINGEDGE);
	ret = ioctl(fd1, SET_FIO_EDGE, LEVEL);

	ret= 0;

	printf("\n\nPress BTN1 to EXIT\n");

  while(!ret) 
  {
		write(fd0,"0",sizeof("0")); 
		usleep(1000);
		write(fd0,"1",sizeof("1"));
		usleep(1000);

		read(fd1,data_read,2);
		if(data_read[0] == '1') 
		  ret=1;
  }

	close(fd1);
	close(fd0);

	exit(0);
}
