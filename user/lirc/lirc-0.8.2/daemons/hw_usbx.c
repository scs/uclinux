/*****************************************************************************
 ** hw_usbx.c ****************************************************************
 *****************************************************************************
 * Routines for the ADSTech USBX-707 USB IR Blaster
 *
 * Only receiving is implemented.
 *
 * It uses a baudrate of 300kps on a USB serial device which, currently, is 
 * only supported by Linux.
 * If someone knows how to set such a baudrate under other OS's, please add 
 * that functionality to daemons/serial.c to make this driver work for those
 * OS's.
 * 
 * Information on how to send with this device is greatly appreciated...
 *
 * Copyright (C) 2007 Jelle Foks <jelle@foks.8m.com>
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
#include "hw_usbx.h"

static unsigned char b[6];
static ir_code code;

#define REPEAT_FLAG ((ir_code) 0x1)
#define CODE_LENGTH 48

struct hardware hw_usbx = {
	LIRC_IRTTY,                      /* Default device */
	-1,                              /* fd */
	LIRC_CAN_REC_LIRCCODE,           /* Features */
	0,                               /* send_mode */
	LIRC_MODE_LIRCCODE,              /* rec_mode */
	CODE_LENGTH,                     /* code_length */
	usbx_init,                       /* init_func */
	NULL,                            /* config_func */
	usbx_deinit,                     /* deinit_func */
	NULL,                            /* send_func */
	usbx_rec,                        /* rec_func */
	usbx_decode,                     /* decode_func */
	NULL,                            /* ioctl_func */
	NULL,                            /* readdata */
	"usbx"
};

int usbx_decode (struct ir_remote *remote, ir_code *prep, ir_code *codep,
		 ir_code *postp, int *repeat_flagp, lirc_t *remaining_gapp)
{
	if( remote->flags&CONST_LENGTH ||
	    !map_code(remote, prep, codep, postp,
		      0, 0, CODE_LENGTH, code&(~REPEAT_FLAG), 0, 0))
	{
                return 0;
	}
	/* the lsb in the code is the repeat flag */
	*repeat_flagp = code&REPEAT_FLAG ? 1:0;
	*remaining_gapp=remote->gap;

	LOGPRINTF(1,"pre: %llx",(unsigned long long) *prep);
	LOGPRINTF(1,"code: %llx",(unsigned long long) *codep);
	LOGPRINTF(1,"post: %llx",(unsigned long long) *postp);
	LOGPRINTF(1,"repeat_flag: %d",*repeat_flagp);
	LOGPRINTF(1,"gap: %lu",(unsigned long) gap);
	LOGPRINTF(1,"rem: %lu",(unsigned long) remote->remaining_gap);
	return 1;
}

int usbx_init(void)
{
	if(!tty_create_lock(hw.device))
	{
		logprintf(LOG_ERR,"could not create lock files for '%s'",
		          hw.device);
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

	if(!tty_reset(hw.fd) ||
	   !tty_setbaud(hw.fd, 300000) ||
	   !tty_setrtscts(hw.fd, 1))
	{
		logprintf(LOG_ERR,"could not configure the serial port for "
			  "'%s'", hw.device);
		usbx_deinit();
		return 0;
	}
	
	return 1;
}

int usbx_deinit (void)
{
	close(hw.fd);
	hw.fd = -1;
	tty_delete_lock();
	return 1;
}

char *usbx_rec (struct ir_remote *remotes)
{
	char        *m;
	int         i, x;

	x = 0;
	for (i = 0 ; i < 6; i++)
	{
		if (i > 0)
		{
			if (!waitfordata(20000))
			{
				LOGPRINTF(LOG_ERR,"timeout reading byte %d",i);
				break;
			}
		}
		if (read(hw.fd, &b[i], 1) != 1)
		{
			LOGPRINTF(LOG_ERR, "reading of byte %d failed.", i);
			usbx_deinit();
			return NULL;
		}
		LOGPRINTF(1, "byte %d: %02x", i, b[i]);
		x++;
	}
	code = 0;
	for ( i = 0 ; i < x ; i++ )
	{
		code =  code << 8;
		code |= ((ir_code) b[i]);
	}

	LOGPRINTF(1," -> %0llx",(unsigned long long) code);

	m = decode_all(remotes);
	return m;
}
