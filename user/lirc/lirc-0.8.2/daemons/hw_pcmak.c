/*      $Id: hw_pcmak.c,v 5.2 2005/07/10 08:34:11 lirc Exp $      */

/****************************************************************************
 ** hw_pcmak.c ***********************************************************
 ****************************************************************************
 *
 * routines for Logitech receiver
 *
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 * 	modified for pcmak serial/USB-ftdi receiver P_awe_L <pablozrudnika@wp.pl>
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
#include "hw_pcmak.h"

#define TIMEOUT 50000

extern struct ir_remote *repeat_remote,*last_remote;

unsigned char b;
struct timeval start,end,last;
lirc_t gap,signal_length;
ir_code pre,code;
int repeat_counter, pressed_key;

struct hardware hw_pcmak=
{
	LIRC_DRIVER_DEVICE,       /* default device */
	-1,                       /* fd */
	LIRC_CAN_REC_LIRCCODE,    /* features */
	0,                        /* send_mode */
	LIRC_MODE_LIRCCODE,       /* rec_mode */
	16,                       /* code_length */
	pcmak_init,               /* init_func */
	NULL,                     /* config_func */
	pcmak_deinit,             /* deinit_func */
	NULL,                     /* send_func */
	pcmak_rec,                /* rec_func */
	pcmak_decode,             /* decode_func */
	NULL,                     /* ioctl_func */
	NULL,                     /* readdata */
	"pcmak"
};

int pcmak_decode(struct ir_remote *remote,
		  ir_code *prep,ir_code *codep,ir_code *postp,
		  int *repeat_flagp,lirc_t *remaining_gapp)
{
	if(!map_code(remote,prep,codep,postp,
		     8,pre,8,code,0,0))
	{
		return(0);
	}

	gap=0;
	if(start.tv_sec-last.tv_sec>=2) /* >1 sec */
	{
		*repeat_flagp=0;
	}
	else
	{
		gap=(start.tv_sec-last.tv_sec)*1000000+
		start.tv_usec-last.tv_usec;

		if(gap<remote->remaining_gap*(100+remote->eps)/100
		   || gap<=remote->remaining_gap+remote->aeps)
			*repeat_flagp=1;
		else
			*repeat_flagp=0;
	}

	*remaining_gapp=is_const(remote) ?
	(remote->gap>signal_length ? remote->gap-signal_length:0):
	remote->gap;

	LOGPRINTF(1,"pre: %llx",(unsigned long long) *prep);
	LOGPRINTF(1,"code: %llx",(unsigned long long) *codep);
	LOGPRINTF(1,"repeat_flag: %d",*repeat_flagp);
	LOGPRINTF(1,"gap: %lu",(unsigned long) gap);
	LOGPRINTF(1,"rem: %lu",(unsigned long) remote->remaining_gap);
	LOGPRINTF(1,"signal length: %lu",(unsigned long) signal_length);

	return(1);
}

int pcmak_init(void)
{
	signal_length=hw.code_length*1000000/1200;

	if(!tty_create_lock(hw.device))
	{
		logprintf(LOG_ERR,"could not create lock files");
		return(0);
	}
	if((hw.fd=open(hw.device,O_RDWR|O_NONBLOCK|O_NOCTTY))<0)
	{
		logprintf(LOG_ERR,"could not open %s",hw.device);
		logperror(LOG_ERR,"pcmak_init()");
		tty_delete_lock();
		return(0);
	}
	if(!tty_reset(hw.fd))
	{
		logprintf(LOG_ERR,"could not reset tty");
		pcmak_deinit();
		return(0);
	}
	if(!tty_setbaud(hw.fd,1200))
	{
		logprintf(LOG_ERR,"could not set baud rate");
		pcmak_deinit();
		return(0);
	}
	return(1);
}

int pcmak_deinit(void)
{
	close(hw.fd);
	tty_delete_lock();
	return(1);
}

char *pcmak_rec(struct ir_remote *remotes)
{
	char *m;
	int i=0;

	last=end;
	gettimeofday(&start,NULL);
	
	while(1)
	{
		i++;
		if(i>0) {
			if(!waitfordata(TIMEOUT)) {
				LOGPRINTF(0,"timeout reading byte %d",i);
				return NULL;
			}
		}

		if(read(hw.fd,&b,1)!=1)  {
			logprintf(LOG_ERR,"reading of byte %d failed",i);
			logperror(LOG_ERR,NULL);
			return NULL;
		}
		LOGPRINTF(1,"byte %d: %02x",i,b);
		if (b == 0xAA) {
			repeat_counter = 0;
		}
		else
		{
			/* Range of allowed button codes */
			if(/* PCMAK codes */
			   (b >= 0x01 && b <= 0x2B) ||
			   /* codes with shift button */
			   (b >= 0x41 && b <= 0x6B) ||
			   /* MINIMAK/MINIMAK LASER codes */
			   (b >= 0x2F && b <= 0x31) ||
			   /* MINIMAK codes with shift */
			   b == 0x5F || b == 0x79 || b == 0x75
			   )
			{
				if(repeat_counter < 1) {
					repeat_counter ++;
					pressed_key = b;
				}
				else {
					if( pressed_key == b) {
						gettimeofday(&end,NULL);
						pre=0xAA;
						code=(ir_code) b;
						m=decode_all(remotes);
						return m;
					}
				}
			}
		}
	}
	return NULL;
}
