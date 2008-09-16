#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <can4linux.h>

#define STDDEV "can0"

int main(int argc,char **argv)
{
int can_fd;		/* CAN file descriptor */
int got;
canmsg_t rx;		/* buffer for received message */
canmsg_t tx;		/* buffer for transmit messsage */
char device[40];	/* string to hold the CAN device Name */
fd_set rfds;		/* file descriptors for select() */
fd_set wfds;		/* file descriptors for select() */
long long count;

    if(argc == 2) {
	sprintf(device, "/dev/%s", argv[1]);
    }
    else {
	sprintf(device, "/dev/%s", STDDEV);
    }
    printf("using CAN device %s, ", device);
    
    if(( can_fd = open(device, O_RDWR )) < 0 ) {
	fprintf(stderr,"Error opening CAN device %s\n", device);
        exit(1);
    }
    printf("got can_fd  %d\n", can_fd);

    /* prepare the fixed part of transmit message */
    tx.id     = 100;
    tx.length = 8;
    tx.flags  = 0;
    count = 0;

    while(1) {
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(can_fd, &rfds);		/* watch on fd for CAN */
        FD_SET(can_fd, &wfds);		/* watch on fd for CAN */
        FD_SET(0, &rfds);		/* watch on fd for stdin */


	if( select(FD_SETSIZE, &rfds, &wfds, NULL,     NULL  ) > 0 )
	if( FD_ISSET(can_fd, &wfds) ) {

	    memcpy(&tx.data[0], &count, 8);
	    write(can_fd, &tx, 1);
	    count++;
	}
	if( FD_ISSET(can_fd, &rfds) ) {

	    got = read(can_fd, &rx, 1);
	    if (rx.id == 0xFFFFFFFF) {
	    	printf(" Error %d\n", rx.flags);
	    	if (rx.flags & MSG_BUSOFF) {
		    printf(" - BUSOFF\n");
	    	}
	    	if (rx.flags & MSG_PASSIVE) {
		    printf(" - ERROR PASSIVE\n");
	    	}
	    }
	}
	if( FD_ISSET(0, &rfds) ) {
	int c, i;
	    /* it was the stdio terminal fd */
	    i = read(0 , &c, 1);
	    printf(" key = %x\n", c);
	} /* stdio fd */
    }


    close(can_fd);
    return 0;
}
