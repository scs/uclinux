/* simple CAN application example 
 * 
 * open CAN and test the write(2) call
 * An calling option  decides if the CAN device is opend for
 * blocking or nonblocking write.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <can4linux.h>

#define STDDEV "can1"
#define VERSION "1.1"

/* #define TXBUFFERSIZE 256 */
#define TXBUFFERSIZE 100

#ifndef TRUE
# define TRUE  1
# define FALSE 0
#endif

int sleeptime            = 1000;	/* standard sleep time */
int debug                = FALSE;
int baud		 = -1;		/* dont change baud rate */
int blocking		 = TRUE;	/* open() mode */
long mcount		 = 100;		/* Number of messages to send */

/* ----------------------------------------------------------------------- */

void usage(char *s)
{
static char *usage_text  = "\
 Open CAN device and send CAN messages\n\
 Default device is /dev/can1. \n\
Options:\n\
-d   - debug On\n\
       swich on additional debugging\n\
-T c - send max c number messages\n\
-b baudrate (Standard uses value of /proc/sys/Can/baud)\n\
-n   - non-blocking mode (default blocking)\n\
-V   version\n\
\n\
";
    fprintf(stderr, "usage: %s [options] [device]\n", s);
    fprintf(stderr, usage_text);
}


/* -s sleep sleep in ms between write() calls in non-blocking mode\n\ */

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
	int fd,			/* device descriptor */
	int baud		/* bit rate */
	)
{
Config_par_t  cfg;
volatile Command_par_t cmd;


    cmd.cmd = CMD_STOP;
    ioctl(fd, CAN_IOCTL_COMMAND, &cmd);

    cfg.target = CONF_TIMING; 
    cfg.val1   = baud;
    ioctl(fd, CAN_IOCTL_CONFIG, &cfg);

    cmd.cmd = CMD_START;
    ioctl(fd, CAN_IOCTL_COMMAND, &cmd);
    return 0;
}


/***********************************************************************
*
* main - 
*
*
*/

int main(int argc,char **argv)
{
int fd;
int i, sent;
int c;
char *pname;
extern char *optarg;
extern int optind;
long count;

canmsg_t tx[TXBUFFERSIZE];
char device[50];

    pname = *argv;

    /* parse command line */
    while ((c = getopt(argc, argv, "b:dhs:nT:V")) != EOF) {
	switch (c) {
	    case 'b':
		baud = atoi(optarg);
		break;
	    case 's':
		sleeptime = atoi(optarg);
		break;
	    case 'd':
		debug = TRUE;
		break;
	    case 'n':
		blocking = FALSE;
		break;
	    case 'T':
	    	mcount = atol(optarg);
	    	break;
	    case 'V':
		printf("%s %s\n", argv[0], " V " VERSION ", " __DATE__ );
		exit(0);
		break;
	    case 'D':
		if (
		    /* path ist starting with '.' or '/', use it as it is */
			optarg[0] == '.'
			|| 
			optarg[0] == '/'
			) {
		    sprintf(device, "%s", optarg);

	        } else {
		    sprintf(device, "/dev/%s", optarg);
		}
		break;
	    case 'h':
	    default: usage(pname); exit(0);
	}
    }

    /* look for additional arguments given on the command line */
    if ( argc - optind > 0 ) {
        /* at least one additional argument, the device name is given */
        char *darg = argv[optind];

	if (
	    /* path ist starting with '.' or '/', use it as it is */
		    darg[0] == '.'
		    || 
		    darg[0] == '/'
		    ) {
		sprintf(device, "%s", darg);
	} else {
	sprintf(device, "/dev/%s", darg);
	}
    } else {
	sprintf(device, "/dev/%s", STDDEV);
    }

    if ( debug == TRUE ) {
	printf("%s %s\n", argv[0], " V " VERSION ", " __DATE__ );
	printf("(c) 1996-2006 port GmbH\n");
	printf(" using canmsg_t with %d bytes\n", sizeof(canmsg_t));
	printf(" max count %ld messages, %d with each write()\n",
			mcount, TXBUFFERSIZE);
	printf(" CAN device %s opened in %sblocking mode\n",
		device, blocking ? "" : "non-");

    }

    sleeptime *= 1000;
    
    if(blocking == TRUE) {
	/* fd = open(device, O_RDWR); */
	fd = open(device, O_RDWR);
    } else {
	fd = open(device, O_RDWR | O_NONBLOCK);
    }
    if( fd < 0 ) {
	fprintf(stderr,"Error opening CAN device %s\n", device);
	exit(1);
    }
    if (baud > 0) {
	if ( debug == TRUE ) {
	    printf("change Bit-Rate to %d Kbit/s\n", baud);
	}
	set_bitrate(fd, baud);
    }

    /* Initialize transmit messages */
    for(i = 0; i < TXBUFFERSIZE; i++) {
        sprintf( tx[i].data, "msg %4d", i);
        tx[i].flags = 0;  
        tx[i].length = strlen(tx[i].data);  
        tx[i].id= i;
    }

    count = 0;

    /* send messages, don't care about non-blocking mode */
    while(1) {

	*(long *)&tx[0].data = count;
	sent = write(fd, &tx, TXBUFFERSIZE );
	if(sent <= 0) {
	    printf("sent %d;", sent); fflush(stdout);
	    perror("sent");
	}
	count += sent;

	if (count >= mcount) {
		/* finished, but sleep to guarantee empty tx buffers */ 
		sleep(1); exit(0);
	}
    }

    close(fd);
    return 0;
}
