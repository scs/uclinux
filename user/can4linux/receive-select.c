#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>

#include <can4linux.h>

#define STDDEV "can0"

int main(int argc,char **argv)
{
int can_fd;			/* CAN file descriptor */
int got;
canmsg_t rx;
char device[40];	/* string to hold the CAN device Name */
fd_set rfds;		/* file descriptors for select() */

    printf("usage: %s <dev>]\n", argv[0]);
    printf("   e.g.:\n");
    printf("   %s /dev/can0\n", argv[0]);
    printf("   wait for CAN messages using select()\n");

    sprintf(device, "%s", argv[1]);
    printf("using CAN device %s, ", device);
    
    if(( can_fd = open(device, O_RDWR )) < 0 ) {
	fprintf(stderr,"Error opening CAN device %s\n", device);
        exit(1);
    }
    printf("got can_fd  %d\n", can_fd);


    while(1) {
        FD_ZERO(&rfds);
        FD_SET(can_fd, &rfds);		/* watch on fd for CAN */
        FD_SET(0, &rfds);		/* watch on fd for stdin */


	if( select(FD_SETSIZE, &rfds, NULL, NULL,     NULL  ) > 0 )
	if( FD_ISSET(can_fd, &rfds) ) {

	    got = read(can_fd, &rx, 1);

	    if( got > 0) {
	    int i;
		printf("Received at "
		"%12lu.%06lu ",
			rx.timestamp.tv_sec,
			rx.timestamp.tv_usec);
		 printf(": %c%c 0x%08lx : %d bytes:",
				       rx.flags & MSG_EXT ? 'x' : 's',
				       rx.flags & MSG_RTR ? 'R' : 'D',
				       rx.id,   rx.length);
		    if(rx.length > 0) {
			printf("\t");
			if(rx.flags & MSG_RTR) {
			    /* dont show date for RTR frames */
			    printf("(RTR no data)");

			} else {
			    for(i = 0; i < rx.length; i++) {
				printf("%02x ", rx.data[i]);
			    }
			}
		    }
		    printf("\n");



		fflush(stdout);
	    } else {
		printf("Received with ret=%d\n", got);
		fflush(stdout);
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
