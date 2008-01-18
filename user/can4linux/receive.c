/* simple CAN application example 
 * 
 * open CAN and test the read(2) call
 * An calling option  decides if the CAN device is opened for
 * blocking or nonblocking read.
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

#define STDDEV "can0"
#define COMMANDNAME "receive"
#define VERSION "1.2"

#define RXBUFFERSIZE 100

#ifndef TRUE
# define TRUE  1
# define FALSE 0
#endif

int sleeptime            = 1000;	/* standard sleep time */
int debug                = FALSE;
int baud		 = -1;		/* dont change baud rate */
int blocking		 = TRUE;	/* open() mode */

/* ----------------------------------------------------------------------- */

void usage(char *s)
{
static char *usage_text  = "\
 Open CAN device and display read messages\n\
 Default device is /dev/can0. \n\
Options:\n\
-d   - debug On\n\
       swich on additional debugging\n\
-b baudrate (Standard uses value of /proc/sys/Can/baud)\n\
-n   - non-blocking mode (default blocking)\n\
-s sleep sleep in ms between read() calls in non-blocking mode\n\
-V   version\n\
\n\
";
    fprintf(stderr, "usage: %s [options] [device]\n", s);
    fprintf(stderr, usage_text);
}



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
int got;
int c;
char *pname;
extern char *optarg;
extern int optind;

canmsg_t rx[RXBUFFERSIZE];
char device[50];
int messages_to_read = 1;

    pname = *argv;

    /* parse command line */
    while ((c = getopt(argc, argv, "b:dhs:nV")) != EOF) {
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
		messages_to_read = RXBUFFERSIZE;
		break;
	    case 'V':
		printf("%s %s\n", argv[0], " V " VERSION ", " __DATE__ );
		exit(0);
		break;

		/* not used, devicename is parameter */ 
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
	printf(" CAN device %s opened in %sblocking mode\n",
		device, blocking ? "" : "non-");

    }

    sleeptime *= 1000;
    
    if(blocking == TRUE) {
	/* fd = open(device, O_RDWR); */
	fd = open(device, O_RDONLY);
    } else {
	fd = open(device, O_RDONLY | O_NONBLOCK);
    }
    if( fd < 0 ) {
	fprintf(stderr,"Error opening CAN device %s\n", device);
	perror("open");
	exit(1);
    }
    if (baud > 0) {
	if ( debug == TRUE ) {
	    printf("change Bit-Rate to %d Kbit/s\n", baud);
	}
	set_bitrate(fd, baud);
    }

    /* printf("waiting for msg at %s\n", device); */

    while(1) {
      got=read(fd, &rx, messages_to_read);
      if( got > 0) {
        int i;
        int j;
        for(i = 0; i < got; i++) {
	    printf("Received with ret=%d: %12lu.%06lu id=%ld\n",
		    got, 
		    rx[i].timestamp.tv_sec,
		    rx[i].timestamp.tv_usec,
		    rx[i].id);

	    printf("\tlen=%d msg=", rx[i].length);
	    for(j = 0; j < rx[i].length; j++) {
		printf(" %02x", rx[i].data[j]);
	    }
	    printf(" flags=0x%02x\n", rx[i].flags );
	    fflush(stdout);
	}
      } else {
	printf("Received with ret=%d\n", got);
	fflush(stdout);
      }
      if(blocking == FALSE) {
	  /* wait some time before doing the next read() */
	  usleep(sleeptime);
      }
    }

    close(fd);
    return 0;
}
