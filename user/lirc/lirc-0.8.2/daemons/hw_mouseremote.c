/*      $Id: hw_mouseremote.c,v 5.4 2005/07/10 08:34:11 lirc Exp $      */

/****************************************************************************
 ** hw_mouseremote.c ********************************************************
 ****************************************************************************
 *
 * routines for X10 Mouse Remote
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 * 	modified for logitech receiver by Isaac Lauer <inl101@alumni.psu.edu>
 *	modified for X10 receiver by Shawn Nycz <dscordia@eden.rutgers.edu>
 *	modified for X10 MouseRemote by Brian Craft <bcboy@thecraftstudio.com>
 *	removed dependency on multimouse by Geoffrey Hausheer <zcke0au02@sneakemail.com>
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

#include <termios.h>
#include <signal.h>

#include "hardware.h"
#include "serial.h"
#include "ir_remote.h"
#include "lircd.h"
#include "hw_mouseremote.h"

#define TIMEOUT 50000

extern struct ir_remote *repeat_remote,*last_remote;

struct timeval start,end,last;
lirc_t gap,signal_length;
ir_code pre,code;
static int serial_input;

struct hardware hw_mouseremote=
{
	LIRC_DRIVER_DEVICE,		/* default device */
	-1,                       	/* fd */
	LIRC_CAN_REC_LIRCCODE,    	/* features */
	0,                        	/* send_mode */
	LIRC_MODE_LIRCCODE,       	/* rec_mode */
	32,				/* code_length */
	mouseremote_init,          	/* init_func */
	NULL,                     	/* config_func */
	mouseremote_deinit,        	/* deinit_func */
	NULL,                     	/* send_func */
	mouseremote_rec,           	/* rec_func */
	mouseremote_decode,        	/* decode_func */
	NULL,                           /* ioctl_func */
	NULL,                     	/* readdata */
	"mouseremote"
};
struct hardware hw_mouseremote_ps2=
{
	"/dev/psaux",			/* default device */
	-1,                       	/* fd */
	LIRC_CAN_REC_LIRCCODE,    	/* features */
	0,                        	/* send_mode */
	LIRC_MODE_LIRCCODE,       	/* rec_mode */
	32,				/* code_length */
	mouseremote_ps2_init,          	/* init_func */
	NULL,                     	/* config_func */
	mouseremote_deinit,        	/* deinit_func */
	NULL,                     	/* send_func */
	mouseremote_rec,           	/* rec_func */
	mouseremote_decode,        	/* decode_func */
	NULL,                           /* ioctl_func */
	NULL,                     	/* readdata */
	"mouseremote_ps2"
};

int mouseremote_decode(struct ir_remote *remote,
		  ir_code *prep,ir_code *codep,ir_code *postp,
		  int *repeat_flagp,lirc_t *remaining_gapp)
{
	if(!map_code(remote,prep,codep,postp,
		     8,0x08,16,code,8,0x7f))
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

int mouseremote_init(void)
{
	serial_input = 1;
	signal_length=hw.code_length*1000000/1200;
	
	if(!tty_create_lock(hw.device))
	{
		logprintf(LOG_ERR,"could not create lock files");
		return(0);
	}
	if((hw.fd=open(hw.device,O_RDWR|O_NONBLOCK|O_NOCTTY))<0)
	{
		logprintf(LOG_ERR,"could not open %s",hw.device);
		logperror(LOG_ERR,"mouseremote_init()");
		tty_delete_lock();
		return(0);
	}
	if(!tty_reset(hw.fd))
	{
		logprintf(LOG_ERR,"could not reset tty");
		mouseremote_deinit();
		return(0);
	}
	if(!tty_setbaud(hw.fd,1200))
	{
		logprintf(LOG_ERR,"could not set baud rate");
		mouseremote_deinit();
		return(0);
	}
	if(!tty_setcsize(hw.fd,7))
	{
		logprintf(LOG_ERR,"could not set character size");
		mouseremote_deinit();
		return(0);
	}
	return(1);
}

int mouseremote_ps2_init(void)
{
	serial_input = 0;
	signal_length=hw.code_length*1000000/1200;
	
	if(!tty_create_lock(hw.device))
	{
		logprintf(LOG_ERR,"could not create lock files");
		return(0);
	}
	if((hw.fd=open(hw.device,O_RDWR|O_NONBLOCK|O_NOCTTY))<0)
	{
		logprintf(LOG_ERR,"could not open %s",hw.device);
		logperror(LOG_ERR,"mouseremote_ps2_init()");
		tty_delete_lock();
		return(0);
	}
	return(1);
}

int mouseremote_deinit(void)
{
	close(hw.fd);
	tty_delete_lock();
	return(1);
}

char *mouseremote_rec(struct ir_remote *remotes)
{
	char *m;
	int i=0, dx = 0, dy = 0, stat = 0;
#define NUMBYTES 3
	unsigned char b[NUMBYTES];

	b[0]=0x08;
	b[2]=0x7f;

	pre=0x08;

	last=end;
	gettimeofday(&start,NULL);
	while(i < 3)
	{
		int val;
		if(!waitfordata(TIMEOUT))
		{
			LOGPRINTF(0,"timeout reading byte %d",i);
			return(NULL);
		}
		if((val=read(hw.fd,&b[i],1))!=1)
		{
                       logprintf(LOG_ERR,"reading of byte %d (%d) failed",i,val);
                       logperror(LOG_ERR,NULL);
                       return(NULL);
		}
                if (i == 0 && (
		       (serial_input  && (b[i] & 0xC0) != 0x40) ||
		       (!serial_input && (b[i] & 0x0C) != 0x08))) {
		continue;
                }
                if(serial_input && 
		   i && ((b[i] & 0x40) || (b[i] == 0x80))) {
			/* the PS/2 initialization isn't unique
			 * enough to check the stream for
	 		 */
			i = 0;
                	continue;
                }
		LOGPRINTF(1,"byte %d: %02x",i,b[i]);
		++i;
	}
	gettimeofday(&end,NULL);

	if(serial_input)
	{
		if (((char)(b[0]) & 0x0c) != 0x0c && 
		    (char)(b[2]) == 0x3f && ((char)(b[2]) & 0x07)) {
			code=(ir_code) (char)(b[1]) | 
			               (((char)(b[0]) & 0x03)<<6);
			LOGPRINTF(1,"result %llx", (unsigned long long) code);
			m=decode_all(remotes);
			return(m);
		}
		stat = ((b[0] & 0x20) >> 3) | 
		       ((b[0] & 0x10) >> 4);
		dx = (char)(((b[0] & 0x03) << 6) | 
		            (b[1] & 0x3F));
		dy = -((char)(((b[0] & 0x0C) << 4) | 
		              (b[2] & 0x3F)));
	} else {
		if((char)b[2] == 0x7f) {
			if ((char)b[0] != 0x08) {
				LOGPRINTF(1,"Bad data");
				return(NULL);
			}
			code = (ir_code)b[1];
			LOGPRINTF(1,"result %llx", (unsigned long long) code);
			m=decode_all(remotes);
			return(m);
		}
		stat = ((b[0] & 0x01) << 2) | 
		        ((b[0] & 0x06) >> 1);
		dx = (char)b[1];
		dy = (char)b[2];
	}
	code = 0;
	if (dy < 0) {
		dy = -dy;
		code |= 0x80;
	}
	if (dx < 0) {
		dx = -dx;
		code |= 0x08;
	}
	if(dy == 1 || dy == 2 || dy == 8) {
		code |= 0x10;
		if (dy == 2 && dx != 1) {
			code |= 0x0200;
		} else if (dy == 8) {
			code |= 0x0400;
		}
	}
	if(dx == 1 || dx == 2 || dx == 8) {
		code |= 0x01;
		if (dx == 2 && dy != 1) {
			code |= 0x0200;
		} else if (dx == 8) {
			code |= 0x0400;
		}
	}
	if (dy == 4 || dy == 16) {
		code |= 0x30;
	} else if (dx == 4 || dx == 16) {
		code |= 0x03;
	}
	if (code != 0) {
		code |= 0x0100;
		LOGPRINTF(1,"result %llx", (unsigned long long) code);
		m=decode_all(remotes);
		return(m);
	} else if (dx == 0 && dy == 0) {
		code = 0x0800 | stat;
		LOGPRINTF(1,"result %llx", (unsigned long long) code);
		m=decode_all(remotes);
		return(m);
	}
	LOGPRINTF(1,"fallthrough is bad!%d %d %d",dx, dy, stat);
	return(NULL);
}
