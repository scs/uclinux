/*
 * linux - device specific part of Horch
 *
 *
 * Copyright (c) 1999-2005 port GmbH, Halle
 *------------------------------------------------------------------
 * $Header$
 *
 *--------------------------------------------------------------------------
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 *
 *
 * modification history
 * --------------------
 * $Log$
 * Revision 1.2  2006/03/30 15:40:47  hennerich
 * Apply horch user application patch/update form port GmbH
 *
 * Revision 1.23.2.3  2006/02/27 11:16:06  hae
 * add GPL header
 * delete old cvs log messages
 * add O_NONBLOCK flag when opening CAN
 * support for blackfin processor
 * remove trailing '
 * ' from version string of /proc/sys/CAN/version
 *
 *
 *
 * This Soucefile contains:
 *
 * - can4linux specific setup
 * - Server mode Loop 
 * - Console Loop
 * - direct access to the can4linux device
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/fcntl.h>

#include "horch_cfg.h"

#include "socklib/socklib.h"

#include <horch.h>
#include "filter/filter.h"
#ifdef CONFIG_COLDFIRE 
# include "led.h"
#endif

#define MAXLINE		1024
#define MSG_TIMEOUT	100

static void clean(void);

static struct timeval	tv, tv_start;
static struct timezone	tz;


static int can_fd;
/* static int server_fd = 1; */

struct sockaddr_in fsin;		/* UDP socket */

/*
 * =========================================================
 * LINUX system specific part
 * =========================================================
 */

/**************************************************************************
*
* set_up - Linux / can4linux specific initialisation
*
* - CAN Schnittstelle
* - Konsole
*
*/
int set_up(void)
{
int ret;
char line[40];

    atexit(clean);

#ifndef SIM
    if(( can_fd = open(device,
		    /* beginnend mit Version 3.3.6 is read() blockierend */
			O_RDWR | O_NONBLOCK
    				)) < 0 ) {
	fprintf(stderr,"Error opening CAN device %s\n", device);
	exit(1);
    }
    if(o_bitrate != 0) {
	sprintf(line,  " %d\n", o_bitrate);
	set_bitrate(line);
    }

#endif

    BDEBUG("message structure canmsg_t has %d bytes\n", sizeof(canmsg_t));


    if(!o_server) {
	/* set terminal mode */
	ret = system("stty cbreak -echo");
	if(ret != 0) {
	    fprintf(stderr, "  system(stty) returns %d\n", ret);
	    fflush(stderr);
	}
    }

    /* pe-set time structures */
    gettimeofday(&tv_start, &tz);
    return 0;
}

/**************************************************************************
*
* clean_up
*
*/
void clean_up(void)
{
#ifndef SIM
    close(can_fd);
#endif
    /* clean(); */ /* clean wird per atexit() eingebunden */
    exit(0);
}

/**************************************************************************
*
* udp_event_loop
*
*/
int    udp_event_loop() {return 0;}

/**************************************************************************
*
* server_event_loop
*
*/
int server_event_loop(void)
{
/*----------------------------------------------------------------*/
int i;                       /* looping index */
char in_line[MAXLINE];		/* command input line from socket to horch */
int ret;
int size;	/* buffer size and filled buffer count */
int idx;	/* index at client list */
unsigned char client; /* loop var */

SOCKET_T * pSocket;


/* extern int so_debug; */
    /* so_debug = 1; */

    /*
     * Open a TCP socket (an Internet stream socket).
     * 
     */
    pSocket = so_open();
    if( pSocket == NULL ) {
	/* Fehlerbehandlung muß noch überarbeitet werden! */
	fprintf(stderr, "Socket open failed: %d\n", errno);
	return 0;
    }

    /* prepare server */
    ret = so_server( pSocket, o_portnumber, &client_fd[0], HORCH_MAX_CLIENTS); 
    if( ret != 0 ) {
	fprintf(stderr, "server failed: %d\n", ret);
	/* so_server() schließt bereits den Socket */
	/* so_close(pSocket); */
	return 0;
    }

    

/*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
{
canmsg_t rx[80];		/* receive buffer for read() */
canmsg_t *prx;			/* pointer to current processed message */
int got;			/* got this number of messages */


    while( read(can_fd, rx , 80 ) > 0); /* flush/remove old messages */

    FD_SET(can_fd, &(pSocket->allset));	/* watch on fd for CAN */

    /* Initialisierung ready */
    printf("Waiting for Connections on Port %d\n", o_portnumber);

    /*
    * loop forever (daemons never die!)
    *
    * the loop is waiting for new client connections or disconnections
    * or new CAN messages arriving 
    */
    for ( ; ; ) {

        size = MAXLINE;
#ifdef __uClinux__
	ret = so_server_doit(pSocket, &idx, &in_line[0], &size, 2);
#else
	ret = so_server_doit(pSocket, &idx, &in_line[0], &size, 0);
#endif

#ifdef DEBUGCODE
	switch (ret)  {
	    case SRET_SELECT_ERROR:
	    	/* z.B. Timer (für Buslastmessung) */
		/* BDEBUG("select returns value < 0\n"); */
		break;
	    case SRET_CONN_FAIL:
		printf("new client connection wasn't possible\n");
		break;
	    case SRET_UNKNOWN_REASON:
		BDEBUG("unknown reason for select interrupt\n");
		break;
	    case SRET_CONN_CLOSED:
		printf("client at idx: %d closed connection\n", idx);
		break;
	    case SRET_CONN_NEW:
		printf("new client idx: %d\n", idx);
		break;
	    case SRET_CONN_DATA:
		BDEBUG("message from fd: %d: idx %d (%d chars): %s\n",
		    client_fd[idx], idx, size, &in_line[0]);
		break;
	    case SRET_SELECT_USER:
		BDEBUG("handle from user\n");
		break;

	    default:
		printf("unknown return value from so_server_doit\n", ret);
	}
#endif

	/*------------------------------------------------------*/
	if( ret == SRET_CONN_NEW) {
		/* new Client - initialize */
	    filter_init(idx);		/* filter */
	    reset_send_line(idx, -1);	/* transmit buffer */

#ifdef CONFIG_COLDFIRE 
	/* Connect LED On */
	    if (led_open() == 0) {
		led_set(LED_STATUS1, LED_ON);
		led_close();
	    }
#endif

	}
	/*------------------------------------------------------*/
	if( ret == SRET_CONN_CLOSED) {
	int f = 0;	/* Flag */
		/* ist noch jemand connected, ansonsten Stop_CAN */
	    for(client = 0; client < HORCH_MAX_CLIENTS; client++) {
		if (client_fd[client] != NO_CLIENT) {
		    f = 1;
		    break;
		}
	    }
	    if (f == 0) {
	    	/* Stop_CAN(); */
#ifdef CONFIG_COLDFIRE 
		if (led_open() == 0) {
		    led_set(LED_STATUS1, LED_OFF);
		    led_close();
		}
#endif	    
	    }
	}
	/*------------------------------------------------------*/
	
	/*------------------------------------------------------*/
	if(ret == SRET_SELECT_USER) {
	    if (FD_ISSET(can_fd, &pSocket->allset))
	    {
		    /* it was the CAN fd */
		got=read(can_fd, rx , MAX_CANMESSAGES_PER_FRAME );

		if( got > 0) {
		    /* got Messages from the read() call */
#ifdef DEBUGCODE 
		    if (debug) {
			/* fprintf(stderr, "--------------\n"); */
			fprintf(stderr, "Received got=%d\n", got);
		    } 
#endif 	/* DEBUGCODE */
		    
		    prx = &rx[0];
		    /* generate stringbuffer for all clients 
		     * of all received messages */
		    for(i = 0; i < got; i++) {
    /* fprintf(stderr, "=> Buffer = %p\n", prx); */
			show_message(prx);
			prx++;		/* next message */
		    }

		    /* send buffer to the clients */
		    for(client = 0; client < HORCH_MAX_CLIENTS; client++) {
			if (client_fd[client] == -1) {
			    continue;
			}

			/* formatted string reaches Buffer end !*/
    /* fprintf(stderr, "=> send line\n"); */
			display_line(client);
		    } /* for all clients */
		} else {
		    /* read returned with error */
		    /* fprintf(stderr, "- Received got = %d\n", got); */
		    /* fflush(stderr); */
		}

	    } /* it was the CAN fd */
	    else {
	    }
	}
	/*------------------------------------------------------*/

	/*------------------------------------------------------*/
        if( ret == SRET_CONN_DATA ) {
	    /* in Idx steht nun der client */

	    for(i = 0; i < size; i++) 
	    {
	    int retval;

		/* read input chars from recv buffer */
		retval = change_format(idx, in_line[i]);
		if(retval == -1) {
#ifdef DEBUGCODE		
		    /* ERROR */		    
		    fprintf(stderr,"change_format returns %d\n", retval);
		    fflush(stderr);
#endif
		    break;
		}
	    }
	} /* Server-in/stdio fd */
	/*------------------------------------------------------*/

    } /* for(; ; ;) */
} /* CAN definitions */
   /************************************/
   /* Shutdown server, should not happen */
   /************************************/

/* TCP_SERVER_DONE: */

    so_close(pSocket);
    return 0;

}

/**************************************************************************
*
* event_loop - Hauptschleife für die Arbeit innerhalb der Konsole
*
* Es wird (intern) immer mit client 0 gearbeitet.
*
*/
void event_loop(void)
{
canmsg_t rx[80];			/* receive buffer for read() */
fd_set rfds;
int got;				/* got this number of messages */
int i = 0;
struct timeval tval;			/* use time out in W32 server */

/* ÄNDERN bzw. es wird immer mit client 0 gearbeitet */
int client = 0;

    /* Konsolen-Ausgabe benutzt Client 0 */	
    client_fd[client] = 1;

    filter_init(client);		/* filter */
    reset_send_line(client, -1); 	/* transmit buffer */
    /* Start_CAN();  */

    /* On LINUX we need no time out for the select call.
     * we either, wiat for:
     * a message arrives on can_fd
     * a key was hit on stdin - fd=0
     */
    tval.tv_sec  = 0;			/* first try it with 1ms */
    tval.tv_usec = 1400;

    while(1) {
        FD_ZERO(&rfds);
        FD_SET(can_fd, &rfds);		/* watch on fd for CAN */
        FD_SET(0, &rfds);		/* watch on fd for stdin */

#if defined(TARGET_LINUX_PPC)
        /* select for:          read, write, except,  timeout */      
        if( select(FD_SETSIZE, &rfds, NULL, NULL,     &tval ) > 0 )
#else
        /* select for:          read, write, except, no-timeout */      
        if( select(FD_SETSIZE, &rfds, NULL, NULL,     NULL  ) > 0 )
#endif
        {
	    /* one of the read file descriptors has changed status */
	    /* fprintf(stderr, "."); fflush(stderr);         */
        
            if( FD_ISSET(can_fd, &rfds) ) {
            	/* it was the CAN fd */

		got=read(can_fd, rx , 20 );
		if( got > 0) {
		    /* Messages in read */
#ifdef DEBUGCODE 
		    if (debug) {
			/* fprintf(stderr, "--------------\n"); */
			fprintf(stderr, "Received got=%d\n", got);
		    } 
#endif 	/* DEBUGCODE */
		    for(i = 0; i < got; i++) {
		        if((rx[i].id < 0) || (filter(client, rx[i].id) == TRUE)) { 
			    /* for all received messages */
			    show_message(&rx[i]);
			}
		    }
		} else {
		    /* read returnd with error */
		    fprintf(stderr,
		    	"- Received got=%d: id=%d len=%d msg='%s' \n",
			    got, rx[i].id, rx[i].length, rx[i].data );
		    fflush(stderr);
		}
	    } /* it was the CAN fd */

            if( FD_ISSET(0, &rfds) ) {
            	/* it was the stdio terminal fd */
            	i = read(0 , device, 40);
            	while(i--) {
		    change_format(client, device[i]);
		} /* while */
	    } /* stdio fd */
	} else {
	    if(o_show_status) {
	    char line[100];
		getStat(line); /* fills line !! */
		sprintf(line,"%s %.1f\n", line, f_busload);
		strcat(send_line[client], line);
		display_line(client);
	    }
	}
    }
}


/**************************************************************************
*
* clean
*
*/
static void clean(void)
{
    if(o_server) {

    } else {
	system("stty sane");
    }
}

/**************************************************************************
*
* show_system_time
*
*/
int show_system_time(char *line)
{
    gettimeofday(&tv, &tz);
    tv.tv_sec -= tv_start.tv_sec;
    /* tv.tv_usec /= 10000; */
    return(sprintf(line, "%12lu.%06lu  ", tv.tv_sec, tv.tv_usec));
    /* return(sprintf(line, "%3d.%02d  ", tv.tv_sec, tv.tv_usec)); */
}

/***********************************************************************
*
* write_message - write a can message with data from line
*
* .B Line
* contains information about a CAN message to be sent
* in ASCII format:
* .sp
* .CS
* [r] id 0{data}8
* .CE
* where r is a optional RTR Flag that has to be set.
* id is the CAN message identifier and data the optional zero to
* eight data bytes.
* the format of all numbers can be C-format decimal or hexa decimal number.
*
* RETURN:
*
*/



#define skip_space(p)  while(*(p) == ' ' || *(p) == '\t' ) (p)++
#define skip_word(p)  while(*(p) != ' ' && *(p) != '\t' ) (p)++

int write_message(
	int format,	/* if true - extended message format */ 
	char *line	/* write parameter line */
	)
{
/* unsigned char data[8] = {8, 7, 6, 5, 4, 3 , 2, 1}; */
char *lptr;
int len = 0;
/* unsigned char **endptr; */
char *endptr;
canmsg_t tx;			/* build transmit message */



    /* May be some check is needed if we have a valid and useful message */

    lptr = &line[0];
    skip_space(lptr);

    tx.flags = 0;
    if(format == 1) {
	tx.flags |= MSG_EXT;
    } else {
    }
    if(*lptr == 'r' || *lptr == 'R') {
	tx.flags |= MSG_RTR;
	skip_word(lptr);
    }
    skip_space(lptr);
    tx.id  = strtoul(lptr, &endptr, 0);
    tx.cob = 0;

    while( lptr != endptr) {
        lptr = endptr;
        tx.data[len] = (signed char)strtol(lptr, &endptr, 0);
	if(lptr != endptr) len++;
	if (len == 8 ) break; 
    }

    tx.length = len;

BDEBUG("Transmit %d, RTR=%s, len=%d\n", tx.id,		\
			((tx.flags == 0) ? "F" : "T"),	\
			tx.length);
			
    len = write(can_fd, &tx, 1);

    if (len < 0) {
    	/* Write Error */
	fprintf(stderr, "Write Error: %d\n", len);
    }
    
    if (len == 0) {
    	/* Transmit Timeout */
	fprintf(stderr, "Write Error: Transmit fehlgeschlagen\n", len);
    }

    return 0;
}	

/***********************************************************************
*
* set_acceptance - sets the CAN registers
*
* .B Line
* contains information about the content of the CAN
* registers "acceptance" and "mask"
* in ASCII format:
* .sp
* .CS
* 0x0707 0x00000000
* 1799
* .CE
* the format can be C-format decimal or hexa decimal number.
*
* Changing these registers is only possible in Reset mode.
*
* RETURN:
*
*/

int	set_acceptance(
	char *line
	)
{
#if CAN4LINUXVERSION > 0x0300
char *lptr;
char *endptr;			/* unsigned char **endptr; */
unsigned int acm = 0xffffffff;
unsigned int acc = 0xffffffff;
Config_par_t  cfg;
volatile Command_par_t cmd;


    lptr = &line[0];

    skip_space(lptr);
    acc  = strtoul(lptr, &endptr, 0);

    lptr = endptr;
    skip_space(lptr);
    acm  = strtoul(lptr, &endptr, 0);
    
    if(debug) {
	printf(" Called set_acceptance() with mask=%x, code=%x\n", acm, acc);
    }

    cmd.cmd = CMD_STOP;
    ioctl(can_fd, CAN_IOCTL_COMMAND, &cmd);
    /* high acceptance, low mask for 11 bit ID */
    cfg.target = CONF_ACC; 
    cfg.val1    = acm;
    cfg.val2    = acc;
    /* fprintf(stderr,"ACM=%04x\n", acm); */
    ioctl(can_fd, CAN_IOCTL_CONFIG, &cfg);

    cmd.cmd = CMD_START;
    ioctl(can_fd, CAN_IOCTL_COMMAND, &cmd);

    return 0;

#else /* CAN4LINUXVERSION > 0x0300 */

    ioctl(can_fd CO_LINE_PARA_ARRAY_INDEX, COMMAND, CMD_START);
    
    return -1;
#endif /* CAN4LINUXVERSION > 0x0300 */
}

/***********************************************************************
*
* set_bitrate - sets the CAN bitrate
*
* .B Line
* contains information about the new bit rate
* in ASCII format:
* .sp
* .CS
* 125
* 500
* 0x31c
* .CE
* the format can be C-format decimal or hexa decimal number.
*
* Changing these registers is only possible in Reset mode.
*
* RETURN:
*
*/

int	set_bitrate(
	char *line
	)
{
#if CAN4LINUXVERSION > 0x0300
extern int o_bitrate;
char *lptr;
char *endptr;			/* unsigned char **endptr; */
Config_par_t  cfg;
volatile Command_par_t cmd;

    /* default */
    o_bitrate = 125;
    
    lptr = &line[0];
    skip_space(lptr);

    o_bitrate  = strtoul(lptr, &endptr, 0);

    if(debug) {
	printf(" Changing Bitrate to %d Kbit/s\n", o_bitrate);
    }

    if(o_bitrate == 0) {
    	/* no change */
    	return -1;
    }

    cmd.cmd    = CMD_STOP;
    ioctl(can_fd, CAN_IOCTL_COMMAND, &cmd);
    
#if CAN4LINUXVERSION > 0x0301
    cfg.cmd    = CAN_IOCTL_CONFIG;
#endif
    cfg.target = CONF_TIMING; 
    cfg.val1   = o_bitrate;
    ioctl(can_fd, CAN_IOCTL_CONFIG, &cfg);

    cmd.cmd    = CMD_START;
    ioctl(can_fd, CAN_IOCTL_COMMAND, &cmd);

    return 0;

#else /* CAN4LINUXVERSION > 0x0301 */

    ioctl(can_fd CO_LINE_PARA_ARRAY_INDEX, COMMAND, CMD_START);
    
    return -1;
#endif /* CAN4LINUXVERSION > 0x0301 */
}



/***********************************************************************
* set_selfreception
*
* toggle the self reception ability of the CAN driver
*
* A message frame sent out by the controller is copied into
* the receive queue after succesful transmission.
*/
void set_selfreception(int v)
{
Config_par_t  cfg;

    if(debug) {
	printf(" set selfreception to %d\n", v);
    }
    cfg.cmd    = CAN_IOCTL_CONFIG;
    cfg.target = CONF_SELF_RECEPTION; 
    cfg.val1   = v;
    ioctl(can_fd, CAN_IOCTL_CONFIG, &cfg);

}

/***********************************************************************
* set_timestamp
*
* toggle the time stamp ability of the CAN driver
*
* A received message is copied with a time information
* into the rx queue.
* This can take some µs. In order to shorten the CAN ISR.
* This can be switched off.
* In this case time stamp information is always zero.
*/
void set_timestamp(int v)
{
Config_par_t  cfg;

    if(debug) {
	printf(" set timestamp to %d\n", v);
    }
    cfg.cmd    = CAN_IOCTL_CONFIG;
    cfg.target = CONF_TIMESTAMP; 
    cfg.val1   = v;
    ioctl(can_fd, CAN_IOCTL_CONFIG, &cfg);

}

/***********************************************************************
* getStat
*
* fill line with status info 
*
* Todo:
* We need to parameters. First the line for the standard information.
* Second a line for additional information. At the moment wie use a
* place holder for the standard information, that the horch add to the
* string. The standard information must have a fix position.
*
* Other solution, getState() fills a structure with all information. 
*
* Problem:
* At the moment the CAN-REport don't work with larger status information
* correctly. Therefore we add this information in a later version.
*/
void getStat(
	char *line
	)
{
#if CAN4LINUXVERSION > 0x0300
CanStatusPar_t status;
#else
CanSja1000Status_par_t status;
#endif
char *m;

    ioctl(can_fd, CAN_IOCTL_STATUS, &status);
    switch(status.type) {
        case  CAN_TYPE_SJA1000:
            m = "sja1000";
            break;
        case  CAN_TYPE_FlexCAN:
            m = "FlexCan";
            break;
        case  CAN_TYPE_TouCAN:
            m = "TouCAN";
            break;
        case  CAN_TYPE_82527:
            m = "I82527";
            break;
        case  CAN_TYPE_TwinCAN:
            m = "TwinCAN";
            break;
        case  CAN_TYPE_BlackFinCAN:
            m = "BlackFin";
            break;
    case CAN_TYPE_UNSPEC:
    default:
            m = "unknown";
            break;
    }
	/* controller / Bitrate / Controller State / Warning Limit /
	   RX Errors / TX Errors / Err Code / place marker for busload /
	   TX Buffers full/max / RX Buffers full/max

	   We need the place holder for the busload, because we
	   want add more information to the string. The busload will
	   added by the horch application.
	 */
# ifdef CONFIG_ADDITIONAL_STATUS_INFO
    /* default - not active! */
    sprintf(line, ":: %s %4d %2d %2d %2d %2d %2d %%s %d/%d %d/%d",
        m,
        status.baud,
        status.status,
        status.error_warning_limit,
        status.rx_errors,
        status.tx_errors,
        status.error_code,
        /* busload */
        status.tx_buffer_used,
        status.tx_buffer_size,
        status.rx_buffer_used
        status.rx_buffer_size,
        );
# else        /* CONFIG_ADDITIONAL_STATUS_INFO */
    sprintf(line, ":: %s %d %d %d %d %d %d",
        m,
        status.baud,
        status.status,
        status.error_warning_limit,
        status.rx_errors,
        status.tx_errors,
        status.error_code
        /* busload */
        );
# endif /* CONFIG_ADDITIONAL_STATUS_INFO */
}

/***********************************************************************
* getLayer2Version
* returns driver related part of version Information
*/
#define MAX_LAYERVERION_STRING 200
const char * getLayer2Version(void)
{
static char s[MAX_LAYERVERION_STRING];
FILE * fd;
char *ps;

    s[0] = 0;
    
    strncat(s, " can4linux Version: ",MAX_LAYERVERION_STRING - strlen(s));

    fd = fopen("/proc/sys/Can/version","r");
    if (fd == NULL) {
	strncat(s, "???", MAX_LAYERVERION_STRING - strlen(s));
    } else {
    	fgets(s + strlen(s), 30, fd);
    	fclose(fd);
    }

    /* change control characters to spaces (e.g. linefeed) */
    ps = &s[0];
    while (*ps != 0) {
    	if (*ps < ' ') {
    	    *ps = ' ';
    	}
    	ps++;
    }
	    
    return s;		
}

