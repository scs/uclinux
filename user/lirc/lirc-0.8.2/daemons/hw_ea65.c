/*
 * Support for builtin key panel and remote control on
 *      AOpen XC Cube EA65, EA65-II
 * 
 * Copyright (C) 2004 Max Krasnyansky <maxk@qualcomm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * $Id: hw_ea65.c,v 5.3 2005/07/10 08:34:11 lirc Exp $
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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

#include "hw_ea65.h"

#define TIMEOUT     60000
#define CODE_LENGTH 24

struct timeval start, end, last;
ir_code code;

struct hardware hw_ea65 =
{
	LIRC_IRTTY,            /* default device */
	-1,                    /* fd             */
	LIRC_CAN_REC_LIRCCODE, /* features       */
	0,                     /* send_mode      */
	LIRC_MODE_LIRCCODE,    /* rec_mode       */
	CODE_LENGTH,           /* code_length    */
	ea65_init,             /* init_func      */
	NULL,                  /* config_func    */
	ea65_release,          /* deinit_func    */
	NULL,                  /* send_func      */
	ea65_receive,          /* rec_func       */
	ea65_decode,           /* decode_func    */
	NULL,                  /* ioctl_func     */
	NULL,                  /* readdata       */
	"ea65"
};

int ea65_decode(struct ir_remote *remote, ir_code *ppre, ir_code *pcode,
		ir_code *ppost, int *repeat, lirc_t *gap)
{
	lirc_t d = 0;

	if (!map_code(remote, ppre, pcode, ppost,
			0, 0, CODE_LENGTH, code, 0, 0))
		return 0;

	if (start.tv_sec - last.tv_sec >= 2) {
		*repeat = 0;
	} else {
		d = (start.tv_sec - last.tv_sec) * 1000000 +
			start.tv_usec - last.tv_usec;
		if (d < 960000)
		{
			*repeat = 1;
		}
		else
		{
			*repeat = 0;
		}
	}
	
	*gap = 0;

	LOGPRINTF(1, "EA65: decode code: %llx", (unsigned long long) *pcode);

	return 1;
}

int ea65_init(void)
{
	logprintf(LOG_INFO, "EA65: device %s", hw.device); 

	if (!tty_create_lock(hw.device)) {
		logprintf(LOG_ERR,"EA65: could not create lock files");
		return 0;
	}

	hw.fd = open(hw.device, O_RDWR | O_NONBLOCK | O_NOCTTY);
	if (hw.fd < 0) {
		logprintf(LOG_ERR,"EA65: could not open %s",hw.device);
		tty_delete_lock();
		return 0;
	}

	if (!tty_reset(hw.fd)) {
		logprintf(LOG_ERR,"EA65: could not reset tty");
		ea65_release();
		return 0;
	}

	if (!tty_setbaud(hw.fd, 9600)) {
		logprintf(LOG_ERR,"EA65: could not set baud rate");
		ea65_release();
		return 0;
	}

	return 1;
}

int ea65_release(void)
{
	close(hw.fd);
	tty_delete_lock();

	return 1;
}

char *ea65_receive(struct ir_remote *remote)
{
	uint8_t data[5];
	int r;

	last = end;
	gettimeofday(&start, NULL);
	
	if (!waitfordata(TIMEOUT)) {
		logprintf(LOG_ERR, "EA65: timeout reading code data");
		return NULL;
	}

	r = read(hw.fd, data, sizeof(data));
	if (r < 4) {
		logprintf(LOG_ERR, "EA65: read failed. %s(%d)",
			  strerror(r), r);
		return NULL;
	}

	LOGPRINTF(1, "EA65: data(%d): %02x %02x %02x %02x %02x", r,
			data[0], data[1], data[2], data[3], data[4]);

	if (data[0] != 0xa0)
		return NULL;

	switch (data[1]) {
	case 0x01:
		if (r < 5)
			return NULL;
		code = (data[2] << 16) | (data[3] << 8) | data[4];
		break;

	case 0x04:
		code = (0xff << 16) | (data[2] << 8) | data[3];
		break;
	}
	logprintf(LOG_INFO, "EA65: receive code: %llx",
		  (unsigned long long) code);

	gettimeofday(&end, NULL);

	return decode_all(remote);
}
