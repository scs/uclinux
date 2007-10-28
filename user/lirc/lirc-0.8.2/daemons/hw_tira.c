/*   $Id: hw_tira.c,v 5.5 2006/07/16 08:37:17 lirc Exp $  */
/*****************************************************************************
 ** hw_tira.c ****************************************************************
 *****************************************************************************
 * Routines for the HomeElectronics TIRA-2 USB dongle.
 *
 * Serial protocol described at: 
 *    http://www.home-electro.com/Download/Protocol2.pdf
 *
 * Copyright (C) 2003 Gregory McLean <gregm@gxsnmp.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
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
#include <errno.h>
#include <termios.h>

#include "hardware.h"
#include "receive.h"
#include "serial.h"
#include "ir_remote.h"
#include "lircd.h"
#include "hw_tira.h"

extern int errno;
struct timeval start,end,last;
unsigned char b[6];
lirc_t gap;
ir_code code;

#define CODE_LENGTH 64
struct hardware hw_tira = {
	"/dev/ttyUSB0",                  /* Default device */
	-1,                              /* fd */
	LIRC_CAN_REC_LIRCCODE,           /* Features */
	0,                               /* send_mode */
	LIRC_MODE_LIRCCODE,              /* rec_mode */
	CODE_LENGTH,                     /* code_length */
	tira_init,                       /* init_func */
	NULL,                            /* config_func */
	tira_deinit,                     /* deinit_func */
	NULL,                            /* send_func */
	tira_rec,                        /* rec_func */
	tira_decode,                     /* decode_func */
	NULL,                            /* ioctl_func */
	NULL,                            /* readdata */
	"tira"
};

int tira_setup(void);

int tira_decode (struct ir_remote *remote, ir_code *prep, ir_code *codep,
		 ir_code *postp, int *repeat_flagp, lirc_t *remaining_gapp)
{
	if( remote->flags&CONST_LENGTH ||
	    !map_code(remote, prep, codep, postp,
		      0, 0, CODE_LENGTH, code, 0, 0))
	{
                return 0;
	}
	if(start.tv_sec-last.tv_sec>=2) /* >1 sec */
	{
		*repeat_flagp=0;
	}
	else
	{
		gap=time_elapsed(&last,&start);
		if(gap<=remote->remaining_gap*(100+remote->eps)/100
		   || gap<=remote->remaining_gap+remote->aeps)
			*repeat_flagp=1;
		else
			*repeat_flagp=0;
	}
	*remaining_gapp=remote->gap;
  
	LOGPRINTF(1,"pre: %llx",(unsigned long long) *prep);
	LOGPRINTF(1,"code: %llx",(unsigned long long) *codep);
	LOGPRINTF(1,"post: %llx",(unsigned long long) *postp);
	LOGPRINTF(1,"repeat_flag: %d",*repeat_flagp);
	LOGPRINTF(1,"gap: %lu",(unsigned long) gap);
	LOGPRINTF(1,"rem: %lu",(unsigned long) remote->remaining_gap);
	return 1;
}

int tira_setup(void)
{
	char response[64+1];
	int  i;
	int ptr;
	
	/* Clear the port of any random data */
	while (read(hw.fd, &ptr, 1) >= 0) ;
	
	/* Start off with the IP command. This was initially used to
	   switch to timing mode on the Tira-1. The Tira-2 also
	   supports this mode, however it does not switch the Tira-2
	   into timing mode.
	*/
	if (write (hw.fd, "IP", 2) != 2)
	{
		logprintf(LOG_ERR, "failed writing to device");
		return 0;
	}
	/* Wait till the chars are written, should use tcdrain but
	   that don't seem to work... *shrug*
	*/
	usleep (2 * (100 * 1000));
	i = read (hw.fd, response, 3);
	if (strncmp(response, "OIP", 3) == 0)
	{
		read (hw.fd, &ptr, 1);   /* read the calibration value */
		read (hw.fd, &ptr, 1);   /* read the version word */
		/* Bits 4:7 in the version word set to one indicates a
		   Tira-2 */
		if (ptr & 0xF0)
		{
			logprintf(LOG_INFO, "Tira-2 detected");
			/* Lets get the firmware version */
			write (hw.fd, "IV", 2);
			usleep (2 * (100 * 1000));
			memset (response, 0, sizeof(response));
			i = read (hw.fd, response, sizeof(response)-1);
			logprintf(LOG_INFO, "firmware version %s", response);
		}
		else
		{
			logprintf(LOG_INFO, "Ira/Tira-1 detected");
		}
		/* According to the docs we can do some bit work here
		   and figure out what the device supports from the
		   version word retrived.
	 
		   At this point we have a Device of some sort. Lets
		   kick it into "Six bytes" mode.
		*/
		if (write(hw.fd, "IR", 2 ) != 2)
		{
			logprintf(LOG_ERR, "failed switching device "
				  "into six byte mod");
			return 0;
		}
		/* wait for the chars to be written */
		usleep (2 * (100 * 1000));
		
		i = read (hw.fd, response, 2);
		if (i != 2)
		{
			logprintf(LOG_ERR, "failed reading response "
				  "to six byte mode command");
			return 0;
		}
		else
		{
			if (strncmp(response, "OK", 2) == 0)
			{
				logprintf(LOG_INFO, "device online, "
					  "ready to receive remote codes");
				return 1;
			}
		}
	}
	logprintf(LOG_ERR, "unexpected response from device");
	return 0;
}

int tira_init(void)
{
	LOGPRINTF (1, "Tira init");
	if(!tty_create_lock(hw.device))
	{
		logprintf(LOG_ERR,"could not create lock files");
		return 0;
	}
	if ( (hw.fd = open (hw.device, O_RDWR | O_NONBLOCK | O_NOCTTY)) < 0)
	{
		tty_delete_lock ();
		logprintf (LOG_ERR, "Could not open the '%s' device",
			   hw.device);
		return 0;
	}
	LOGPRINTF(1, "device '%s' opened", hw.device);

	/* We want 9600 8N1 with CTS/RTS handshaking, lets set that
	 * up. The specs state a baud rate of 100000, looking at the
	 * ftdi_sio driver it forces the issue so we can set to what
	 * we would like. And seeing as this is mapped to 9600 under
	 * windows should be a safe bet.
	 */
	if(!tty_reset(hw.fd) ||
	   !tty_setbaud(hw.fd, 9600) ||
	   !tty_setrtscts(hw.fd, 1))
	{
		tira_deinit();
		return 0;
	}
	
	/* Device should be activated by this point... wait... */
	usleep (50000);
	
	if(!tira_setup())
	{
		tira_deinit();
		return 0;
	}
	return 1;
}

int tira_deinit (void)
{
	close(hw.fd);
	sleep(1);
	tty_delete_lock();
	return 1;
}

char *tira_rec (struct ir_remote *remotes)
{
	char        *m;
	int         i, x;

	last = end;
	x = 0;
	gettimeofday (&start, NULL);
	for (i = 0 ; i < 6; i++)
	{
		if (i > 0)
		{
			if (!waitfordata(20000))
			{
				LOGPRINTF(0,"timeout reading byte %d",i);
				/* likely to be !=6 bytes, so flush. */
				tcflush(hw.fd, TCIFLUSH);
				return NULL;
			}
		}
		if (read(hw.fd, &b[i], 1) != 1)
		{
			logprintf(LOG_ERR, "reading of byte %d failed.", i);
			logperror(LOG_ERR,NULL);
			return NULL;
		}
		LOGPRINTF(1, "byte %d: %02x", i, b[i]);
		x++;
	}
	gettimeofday(&end,NULL);
	code = 0;
	for ( i = 0 ; i < x ; i++ )
	{
		code |= ((ir_code) b[i]);
		code =  code << 8;
	}

	LOGPRINTF(1," -> %0llx",(unsigned long long) code);

	m = decode_all(remotes);
	return m;
}
