/*      $Id: hw_caraca.c,v 1.6 2005/07/10 08:34:11 lirc Exp $   */

/****************************************************************************
 ** hw_caraca.c ***********************************************************
 ****************************************************************************
 *
 * routines for caraca receiver 
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 * 	modified for caraca RC5 receiver by Konrad Riedel <k.riedel@gmx.de> 
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include "hardware.h"
#include "serial.h"
#include "ir_remote.h"
#include "lircd.h"
#include "hw_caraca.h"
#include <caraca/caraca_client.h>


#define NUMBYTES 34 
#define TIMEOUT 20000

extern struct ir_remote *repeat_remote,*last_remote;

unsigned char msg[NUMBYTES];
struct timeval start,end,last;
lirc_t gap,signal_length;
ir_code pre,code;

struct hardware hw_caraca=
{
	NULL,                     /* default device */
	-1,                       /* fd */
	LIRC_CAN_REC_LIRCCODE,    /* features */
	0,                        /* send_mode */
	LIRC_MODE_LIRCCODE,       /* rec_mode */
	16,                       /* code_length */
	caraca_init,              /* init_func */
	NULL,                     /* config_func */
	caraca_deinit,            /* deinit_func */
	NULL,                     /* send_func */
	caraca_rec,               /* rec_func */
	caraca_decode             /* decode_func */
	NULL,                     /* ioctl_func */
	NULL,                     /* readdata */
	"caraca"
};

int caraca_decode(struct ir_remote *remote,
		  ir_code *prep,ir_code *codep,ir_code *postp,
		  int *repeat_flagp,lirc_t *remaining_gapp)
{
	*prep=pre;
	*codep=code;
	*postp=0;

	gap=0;
	if(start.tv_sec-last.tv_sec>=2) /* >1 sec */
	{
		*repeat_flagp=0;
	}
	else
	{
		gap=(start.tv_sec-last.tv_sec)*1000000+
		start.tv_usec-last.tv_usec;
		
		if(gap<120000)
			*repeat_flagp=1;
		else
			*repeat_flagp=0;
	}
	
	*remaining_gapp=0;
	LOGPRINTF(1,"code: %llx",(unsigned long long) *codep);
	return(1);
}

int caraca_init(void)
{
	signal_length=hw.code_length*1000000/1200;
	if ( (hw.fd = caraca_open(PACKAGE)) < 0) {
		logprintf(LOG_ERR,"could not open lirc");
		logperror(LOG_ERR,"caraca_init()");
		return(0);
	}
	/*accept IR-Messages (16 : RC5 key code) for all nodes on the bus */
	if(set_filter(hw.fd,0x400,0x7c0,0) <= 0)
	{
		logprintf(LOG_ERR,"could not set filter for IR-Messages");
		caraca_deinit();
		return(0);
	}
	return(1);
}

int caraca_deinit(void)
{
	close(hw.fd);
	return(1);
}

char *caraca_rec(struct ir_remote *remotes)
{
	char *m;
	int i=0,node,ir,t;
	int repeat, mouse_event;

	last=end;
	gettimeofday(&start,NULL);
	i=read(hw.fd,msg,NUMBYTES);
	gettimeofday(&end,NULL);
	
	LOGPRINTF(1,"caraca_rec: %s", msg);
	sscanf(msg,"%d.%d:%d",&node,&t,&ir);

        /* transmit the node address as first byte, so we have
	 * different codes for every transmitting node (for every room
	 * of the house) */
	
	code=(ir_code) (node << 8) + ir;

	m=decode_all(remotes);
	return(m);
}
