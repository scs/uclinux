/* simple driver test: change the bit rate registers with ioctl()
* 
*
* first argument can be the device name -- else it uses can0
*
* if a second arg is given, it is used as new bit rate
*
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <can4linux.h>

#define STDDEV "can0"

/***********************************************************************
*
* set_bitrate - sets the CAN bit rate
*
*
* Changing these registers only possible in Reset mode.
*
* RETURN:
*
*/

int	set_bitrate(
	int can_fd,			/* device descriptor */
	int baud		/* bit rate */
	)
{
Config_par_t  cfg;
volatile Command_par_t cmd;


    cmd.cmd = CMD_STOP;
    ioctl(can_fd, CAN_IOCTL_COMMAND, &cmd);

    cfg.target = CONF_TIMING; 
    cfg.val1   = baud;
    ioctl(can_fd, CAN_IOCTL_CONFIG, &cfg);

    cmd.cmd = CMD_START;
    ioctl(can_fd, CAN_IOCTL_COMMAND, &cmd);
    return 0;
}



/*
*
*
*/
int main(int argc,char **argv)
{
int can_fd;
char device[40];
int newbaud = 250;

    printf("usage: %s [dev] [bit_rate]\n", argv[0]);
    printf("   e.g.:\n");
    printf("   ./baud /dev/can0 125\n");
    printf("   sends out a message at /dev/can0 with 125Kbit/s\n");
    printf("   which can be watched at the CAN cable using an scope\n\n");

    sprintf(device, "%s", argv[1]);
    printf("using CAN device %s\n", device);
    
    if(( can_fd = open(device, O_RDWR )) < 0 ) {
	fprintf(stderr,"Error opening CAN device %s\n", device);
        exit(1);
    }
    if(argc == 3) {
    	newbaud = atoi(argv[2]);
    }
    printf("set baudrate to %d Kbit/s\n", newbaud);
    set_bitrate(can_fd, newbaud);


    /* Use the new CAB nit rate to send one message 
     * If no other CAN node is connected, we can see this mesage
     * using an oscilloscope and we can measure the bit rate 
     */
    {
    canmsg_t txmsg;
    int ret;

    	txmsg.id = 0x55;
    	txmsg.flags = 0;
    	txmsg.length = 8;
    	txmsg.data[0] = 0x55;
    	txmsg.data[1] = 0x55;
    	txmsg.data[2] = 0x55;
    	txmsg.data[3] = 0x55;
    	txmsg.data[4] = 0x55;
    	txmsg.data[5] = 0x55;
    	txmsg.data[6] = 0x55;
    	txmsg.data[7] = 0x55;

	ret = write(can_fd, &txmsg, 1);
	if (ret == -1) {
	    /* int e = errno; */
	    perror("write error");
	    /* } */
	} else if (ret == 0) {
	    printf("transmit timed out\n");
	} else {
	}
    }

    sleep(30);    
    close(can_fd);
    return 0;
}

