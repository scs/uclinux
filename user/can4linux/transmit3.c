/*   Transmit3 sends a CAN message specified at the command line       */
/*   It is using the SEND ioctl command                                */
/*   (c) 2003 port GmbH                                                */

 
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <can4linux.h>


#define STDDEV "/dev/can1"

#ifndef TRUE
# define TRUE  1
# define FALSE 0
#endif


int can_fd;
int debug                = FALSE;
int extd                 = FALSE;
int rtr                  = FALSE;

canmsg_t message;

void usage(char *s)
{
static char *usage_text  = "\
-r send message as rtr message.\n\
-e send message in extended message format.\n\
-d   - debug On\n\
       schaltet zusaetzlich Debugging im Treiber an/aus\n\
-D dev use /dev/dev/{can0,can1,can2,can3} (real nodes, std: can1)\n\
\n\
";
    fprintf(stderr, "usage: %s [options] [id [ byte ..]]\n", s);
    fprintf(stderr, usage_text);
}

int main(int argc,char **argv)
{
int c;
extern char *optarg;
extern int optind, opterr, optopt;
int cnt;
char device[40] = STDDEV;
Send_par_t SendTeil;

    /* our default 8 byte message */
    message.id      = 100;
    message.cob     = 0;
    message.flags   = 0;
    message.length  = 8;
    message.data[0] = 0x55;
    message.data[1] = 2;
    message.data[2] = 3;
    message.data[3] = 4;
    message.data[4] = 5;
    message.data[5] = 6;
    message.data[6] = 7;
    message.data[7] = 0xaa;

    while ((c = getopt(argc, argv, "derD:")) != EOF) {
	switch (c) {
	    case 'r':
		rtr = TRUE;
		break;
	    case 'e':
		extd = TRUE;
		break;
	    /* case 'b': */
		/* baud = atoi(optarg); */
		/* break; */
	    case 'D':
		sprintf(device, "/dev/%s", optarg);
		break;
	    case 'd':
		debug = TRUE;
		break;
	    case 'h':
	    default: usage(argv[0]); exit(0);
	}
    }

    if(debug) printf("using CAN device %s\n", device);

    if(( can_fd = open(device, O_RDWR )) < 0 ) {
	fprintf(stderr,"Error opening CAN device %s\n", device);
        exit(1);
    }

    if ( argc - optind > 0 ) {
        /* at least one additional argument, the message id is given */
	message.id =  strtol(argv[optind++], NULL, 0);
    	memset(message.data, 0, 8);
	message.length = 0;
    }
    if ( argc - optind > 0 ) {
    	/* also data bytes areg given with the command */
	cnt = 0;
	while(optind != argc) {
	    message.data[cnt++] = strtol(argv[optind++], NULL, 0);
	}
	message.length = cnt;
    }
    if (rtr) {
	message.flags |= MSG_RTR;
    }
    if (extd) {
	message.flags |= MSG_EXT;
    }

    if ( debug == TRUE ) {
	printf("transmit3 " __DATE__ "\n");
	printf("(c) 2003 port GmbH\n");
	printf(" using canmsg_t with %d bytes\n", sizeof(canmsg_t));
    }

    SendTeil.Tx = &message;
    cnt = ioctl(can_fd, SEND, &SendTeil);

    if(debug) {
	printf("CAN Send retuned with %d/0x%x\n", cnt, cnt);
    }

    usleep(10000);
    close(can_fd);
    return 0;
}

