/* can driver
*  communication verify program
*  reveives and verifies CAN messages
* 
* To do: ??
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <errno.h>
#include "can4linux.h"


#define STDDEV "/dev/can0"
#define VERSION "1.0"

#define SEQN	9 /* number of messages for one sequence, one write call */

#ifndef TRUE
# define TRUE  1
# define FALSE 0
#endif

extern int errno;
void sbuf(unsigned char *s, int n);
void usage(char *s);
int can_fd;
int debug                = FALSE;
int extd                 = FALSE;
int rtr                  = FALSE;
int baud		 = 0;		/* dont change baud rate */
int cstdout              = FALSE;	/* use stdout for CAN message */

int errs                 = 0;		/* recognized errors */

/* functions */
void clean_process(void);

void verify_message(canmsg_t *m)
{
int i;
static int iseq = 0;			/* received message */
static unsigned long long seq = 0;	/* received sequence */
static unsigned int id = 0;		/* next expected id  */

    if(debug) {
	/* Then show the messages */
	printf("%10ld/0x%08lx : %d : ", m->id, m->id, m->length);
	for(i = 0; i < m->length; i++) {
	    printf("%02x ", m->data[i]);
	}
	printf("\n");
	fflush(stdout);
    }
    if( id != m->id) {
	printf("wrong message Id received: %0lx, expected %0x, in seq %lld\n",
		m->id, id, seq);
        errs++;
        id = m->id; /* try to synchronize */
    }
    if( iseq != m->length ) {
	printf("wrong message length: %d, expected %d, in seq %lld\n",
		m->length, iseq, seq);
    } else {
	i = 1;
	/* check also data content, must be sequence number */
	switch(m->length) {
	   case 0:
	    break;
	   case 1:
	    i = ((seq & 0xff) == m->data[0]);
	    break;
	   case 2:
	    i = ((seq & 0xffff) == *(unsigned short int *)&m->data[0]);
	    break;
	   case 3:
	    break;
	   case 4:
	    i = ((seq & 0xffffffff) == *(unsigned int *)&m->data[0]);
	    break;
	   case 5:
	    break;
	   case 6:
	    break;
	   case 7:
	    break;
	   case 8:
	    i = ((seq) == *(unsigned long long *)&m->data[0]);
	    break;
	}
	if(!i) {
		printf("----wrong data, %d exp: %lld\n",m->length, seq);
	}
	if( ++iseq == SEQN) {
	    iseq = 0;
	    seq++;
	    printf(" seq %lld\n", seq);
	}
    }
    if (    ( extd && (id == (536870906  /* - SEQN */))) 
	 || (!extd && (id == (     2042  /* - SEQN */)))  ) {
	/* reset message id to 0 */
	id = 0;
    } else {
	id++;
    }


}

/**
*
* Receive and verify CAN messages
*
*/
void verify(void)
{
canmsg_t rx[80];			/* receive buffer for read() */
fd_set rfds;
int got;				/* got this number of messages */
int i, fac;
struct timeval tval;		/* use time out in W32 server */


    tval.tv_sec = 0;		/* first try it with 1ms */
    tval.tv_usec = 1400;
    if(cstdout == TRUE) {
	/* use stdout */
	fac = sizeof(canmsg_t);
    } else {
	fac = 1;
    }

    if(debug) {
	printf("==> waiting for messages \n");
    }
    while(1) {
        FD_ZERO(&rfds);
        FD_SET(can_fd, &rfds);		/* watch on fd for CAN */

#if defined(TARGET_LINUX_PPC)
        /* select for:          read, write, except,  timeout */      
        if( select(FD_SETSIZE, &rfds, NULL, NULL,     &tval ) > 0 )
#else
        /* select for:          read, write, except, no-timeout */      
        if( select(FD_SETSIZE, &rfds, NULL, NULL,     NULL  ) > 0 )
#endif
        {
            if( FD_ISSET(can_fd, &rfds) ) {
            	/* it was the CAN fd */
		got=read(can_fd, rx , SEQN * fac);
		/* printf("received %d messages\n", got / fac); */
		printf("%d ", got / fac); fflush(stdout);
		if(got > 0) {
		    ;
		} else break;
		for(i = 0; i < (got / fac); i++) {
		    /* for all received messages */
		    verify_message(&rx[i]);
		}
		
	    } /* was CAN */
        }  /* select() */
    } /* while() */
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
    ioctl(fd, COMMAND, &cmd);

    cfg.target = CONF_TIMING; 
    cfg.val1   = baud;
    ioctl(fd, CONFIG, &cfg);

    cmd.cmd = CMD_START;
    ioctl(fd, COMMAND, &cmd);
    return 0;
}

/**
*
* The main program
*
*/
int main(int argc, char **argv)
{

int ret;
int c;
char *pname;
extern char *optarg;
extern int optind;
char device[40] = STDDEV;

    pname = *argv;

    while ((c = getopt(argc, argv, "b:dehrs:n:D:t:T:V")) != EOF) {
	switch (c) {
	    case 'e':
		extd = TRUE;
		break;
	    case 'b':
		baud = atoi(optarg);
		break;
	    case 'D':
	        if(0 == strcmp(optarg, "stdin")) {
	            cstdout = TRUE;
	            strcpy(device, optarg);
	        } else {
		    sprintf(device, "/dev/%s", optarg);
		}
		break;
	    case 'd':
		debug = TRUE;
		break;
	    case 'V':
		printf("%s Can_verify V" VERSION "\n", pname);
		exit(0);
		break;
	    case 'h':
	    default: usage(pname); exit(0);
	}
    }


    if( argc - optind > 0 ) {
        /* at least one additional argument, the message id is given */
        ;
    }
    if( argc - optind > 0 ) {
    	/* also data bytes areg given with the command */
    	;
    }

    if(debug) {
	printf("Can_verify, (c) 2002 port GmbH\n");
	printf(" using canmsg_t with %d bytes\n", sizeof(canmsg_t));
    }

    if(cstdout == FALSE) {
        /* really use CAN, open the device driver */
	can_fd = open(device, O_RDWR);
	if(can_fd == -1) {
	    fprintf(stderr, "open error %d;", errno);
	    perror(device);
	    exit(1);
	}
	if(debug) {
	    printf("opened %s succesful, got can_fd = %d\n", device, can_fd);
	}
	if(baud != 0) {
	    if(debug) {
		printf("change Bit-Rate to %d Kbit/s\n", baud);
	    }
	    set_bitrate(can_fd, baud);

	}
    } else {
	can_fd = 0;		/* use stdin */
    }

    verify();

/*-------------------------------------------*/
    ret = close(can_fd);
    if(ret == -1) {
	fprintf(stderr, "close error %d;", errno);
	perror("");
	exit(1);
    }
    if(debug) {
	printf("closed fd = %d succesful\n", can_fd);
    }
    return 0;
}


/* show buffer in hex */
void sbuf(unsigned char *s, int n)
{
int i;

    for(i = 0; i< n; i++) {
	fprintf(stdout, "%02x ", *s++);
    }
    putchar('\n');
}



void usage(char *s)
{
static char *usage_text  = "\
 Receive Messages sent by can_send -t10\n\
 The program must be started before can_send\n\
-e   - expect messages in extended message format.\n\
-d   - debug On\n\
-b baudrate (Standard 125)\n\
-D dev use /dev/dev/{can0,can1,can2,can3} (real nodes, std: can1)\n\
      special effect with -D stdin\n\
-V   - show version\n\
\n\
";
    fprintf(stderr, "usage: %s options\n", s);
    fprintf(stderr, usage_text);
}

#if 0

/* Test 10


You can see the output in hexformat by calling
             +- select test type
             |      +-- send messages to
             |      |        +- number of sequences a 9 messages ( 2 * 9)
             |      |        |     +- time in ms between sequences
             |      |        |     |
$ can_send -t10 -D stdout -T 2 -s 100 | od -t x1 -w32
                                         |   |     |
                                         |   |     +-- 32 bytes per line == 
                                         |   |         one message
                                         |   +-- type hex, one byte
                                         +- use "object dump" for display


*/

void test10(void)
{
long int test_count = 0;
int ret, i;
unsigned int cnt = 0;
int fac = 1;

#define SEQN	9 /* number of messages for one sequence, one write call */

canmsg_t tm[SEQN] =  {
    /*  f, cob,  id, time,   l,   data[8]                     */
    {  0 ,   0,   0, {0 , 0},  0, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   1, {0 , 0},  1, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   2, {0 , 0},  2, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   3, {0 , 0},  3, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   4, {0 , 0},  4, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   5, {0 , 0},  5, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   6, {0 , 0},  6, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   7, {0 , 0},  7, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   8, {0 , 0},  8, { 0, 0, 0, 0, 0, 0, 0, 0} }};
#if 0
    int             flags;
    int             cob;	 /**< CAN object number, used in Full CAN  */
    unsigned   long id;		 /**< CAN message ID, 4 bytes  */
    struct timeval  timestamp;	 /**< time stamp for received messages */
    short      int  length;	 /**< number of bytes in the CAN message */
    unsigned   char data[CAN_MSG_LENGTH]; /**< data, 0...8 bytes */
#endif
    if(cstdout == TRUE) {
	can_fd = 1;		/* use stdout */
	fac = sizeof(canmsg_t);
    } else {

    }
    if(extd) {
	/* set the extd flag in all messages */
	for (i = 0; i < SEQN; i++) {
		tm[i].flags |= MSG_EXT;
	}
    }

    /* loop forever if sleeptime > 0 */
    do {
	ret = write(can_fd, &tm[0], SEQN * fac);
	if (++test_count == test_count_soll) {
	    break;
	}
	/* calculate next sequence */
	/* first: new message id */

				    /* ((2^11)/9)*9 - 1   
				     * ((2*29)/9)*9 - 1
				     */
	if (    ( extd && (tm[0].id > (536870906 - SEQN))) 
	     || (!extd && (tm[0].id > (     2042 - SEQN)))  ) {
	    /* reset message id to 0 */
	    for (i = 0; i < SEQN; i++) {
		tm[i].id = i;
	    }
	} else {
	    /* not wrapped, increment message id */
	    for (i = 0; i < SEQN; i++) {
		    tm[i].id += SEQN;
	    }
	}

	/* now update data bytes with counter value */
	for (i = 0; i < SEQN; i++) {
	    *(unsigned long long *)&tm[i].data[0] += 1;
	}

	/* if neccessary sleep */
	if(sleeptime > 0) usleep(sleeptime);
    }
    while(sleeptime > 0);

}
#endif
