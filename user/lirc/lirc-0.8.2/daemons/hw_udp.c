/****************************************************************************
 ** hw_udp.c ****************************************************************
 ****************************************************************************
 *
 * receive mode2 input via UDP
 * 
 * Copyright (C) 2002 Jim Paris <jim@jtan.com>
 *
 * Distribute under GPL version 2 or later.
 *
 * Received UDP packets consist of some number of LE 16-bit integers.
 * The high bit signifies whether the received signal was high or low;
 * the low 15 bits specify the number of 1/16384-second intervals the
 * signal lasted.
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include <errno.h>

#include "hardware.h"
#include "ir_remote.h"
#include "lircd.h"
#include "receive.h"
#include "transmit.h"
#include "hw_default.h"

static int zerofd;       /* /dev/zero */
static int sockfd;       /* the socket */

int udp_init()
{
	int port;
	struct sockaddr_in addr;

	logprintf(LOG_INFO,"Initializing UDP: %s",hw.device);
	
	init_rec_buffer();
	
	port=atoi(hw.device);
	if(port==0) {
		logprintf(LOG_ERR,"invalid port: %s",hw.device);
		return 0;
	}

	/* hw.fd needs to point somewhere when we have extra data */
	if((zerofd=open("/dev/zero",O_RDONLY))<0) {
		logprintf(LOG_ERR,"can't open /dev/zero: %s",
			  strerror(errno));
		return 0;
	}

	if((sockfd=socket(AF_INET,SOCK_DGRAM,0))<0) {
		logprintf(LOG_ERR,"error creating socket: %s",
			  strerror(errno));
		close(zerofd);
		return 0;
	}
	
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port        = htons(port);
	
	if(bind(sockfd,(struct sockaddr *)&addr,sizeof(addr))<0) {
		logprintf(LOG_ERR,"can't bind socket to port %d: %s",
			  port,strerror(errno));
		close(sockfd);
		close(zerofd);
		return 0;
	}
	
	logprintf(LOG_INFO,"Listening on port %d/udp",port);

	hw.fd=sockfd;

	return(1);
}

int udp_deinit(void)
{
	close(sockfd);
	close(zerofd);
	hw.fd=-1;
	return(1);
}

char *udp_rec(struct ir_remote *remotes)
{
	if(!clear_rec_buffer()) return(NULL);
	return(decode_all(remotes));
}

int udp_decode(struct ir_remote *remote,
	       ir_code *prep,ir_code *codep,ir_code *postp,
	       int *repeat_flagp,lirc_t *remaining_gapp)
{
	return(receive_decode(remote,prep,codep,postp,
			      repeat_flagp,remaining_gapp));
}

lirc_t udp_readdata(lirc_t timeout)
{
	static u_int8_t buffer[8192];
	static int buflen=0;
	static int bufptr=0;
	lirc_t data;
	u_int8_t packed[2];
	u_int32_t tmp;
	fd_set rfd;
	struct timeval tv;

	/* Assume buffer is empty; LIRC should select on the socket */
	hw.fd=sockfd;

	/* If buffer is empty, get data into it */
	if((bufptr+2)>buflen) 
	{
		FD_ZERO(&rfd);
		FD_SET(sockfd,&rfd);
		tv.tv_sec=0;
		tv.tv_usec=timeout;
		if(select(sockfd+1,&rfd,NULL,NULL,&tv)!=1) 
			return 0;
		if((buflen=recv(sockfd,&buffer,sizeof(buffer),0))<0)
		{
			logprintf(LOG_INFO,"Error reading from UDP socket");
			return 0;
		}
		if(buflen&1) 
			buflen--;
		if(buflen==0)
			return 0;
		bufptr=0;
	}

	/* Read as 2 bytes to avoid endian-ness issues */
	packed[0]=buffer[bufptr++];
	packed[1]=buffer[bufptr++];

	/* TODO: This assumes the receiver is active low.  Should 
	   be specified by user, or autodetected.  */
	data = (packed[1] & 0x80) ? 0 : PULSE_BIT;

	/* Convert 1/16384-seconds to microseconds */
	tmp = (((u_int32_t)packed[1])<<8) | packed[0];
	/* tmp = ((tmp & 0x7FFF) * 1000000) / 16384; */
	/* prevent integer overflow: */
	tmp = ((tmp & 0x7FFF) * 15625) / 256;

	data |= tmp & PULSE_MASK;

	/* If our buffer still has data, give LIRC /dev/zero to select on */
	if((bufptr+2)<=buflen)
		hw.fd=zerofd;
	
	return(data);
}

struct hardware hw_udp=
{
	"8765",	    	    /* "device" (port) */
	-1,                 /* fd (socket) */
	LIRC_CAN_REC_MODE2, /* features */
	0,                  /* send_mode */
	LIRC_MODE_MODE2,    /* rec_mode */
	0,                  /* code_length */
	udp_init,	    /* init_func */
	NULL,		    /* config_func */
	udp_deinit,         /* deinit_func */
	NULL,		    /* send_func */
	udp_rec,            /* rec_func */
	udp_decode,         /* decode_func */
	NULL,               /* ioctl_func */
	udp_readdata,       /* readdata */
	"udp"
};
