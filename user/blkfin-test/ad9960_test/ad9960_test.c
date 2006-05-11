#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

int
main(int argc,char *argv[])
{
	int	fd;
	int 	retval;
	int 	i;
	char	command[6];
	unsigned short buf[1024];
	int	num;


	if(argc < 3){
		printf("Usage: %s [read | write] number\n", argv[0]);
		return 0;
	}else{
		strcpy(command, argv[1]);
	}
	
	num = atoi(argv[2]);

	fd = open("/dev/ad9960", O_RDWR);

	if (fd < 0)
	{
		perror("Error opening /dev/ad9960");
		return(-1);
	}
	if(!strcmp(command, "read")){
		if(read(fd,buf,num)<0)
			perror("read error\n");
	}
	if(!strcmp(command, "write")){
		for(i=0;i<num;i++)
			buf[i]= i;
		if(write(fd,buf,num)<0)
			perror("write error\n");
	}

	retval = close(fd);
	if(retval)
		perror("ppi close error");

	if(!strcmp(command, "read")){
		printf("buffer is:\n");

	        for(i=0;i<num;i++){
        	        if(i%10 == 0)
                	        printf("\n");
	                printf("0x%-8x\n", buf[i]);
		}
        }

	return (0);
}
