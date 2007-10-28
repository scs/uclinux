/*      $Id: hw_uirt2_common.c,v 5.5 2006/11/22 21:28:39 lirc Exp $   */

/****************************************************************************
 ** hw_uirt2_common.c *******************************************************
 ****************************************************************************
 *
 * Routines for UIRT2 receiver/transmitter
 *
 * UIRT2 web site: http://users.skynet.be/sky50985/
 * 
 * Copyright (C) 2003 Mikael Magnusson <mikma@users.sourceforge.net>
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
# include <config.h>
#endif
//#define DEBUG

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include "serial.h"
#include "lircd.h"
#include "hw_uirt2_common.h"

#define PRINT_TIME(a) \
LOGPRINTF(1, "time: %s %li %li", #a, (a)->tv_sec, (a)->tv_usec)

#ifdef DEBUG
#define HEXDUMP(buf, len) hexdump(buf, len)
#else
#define HEXDUMP(buf, len)
#endif

struct tag_uirt2_t {
	int fd;
	int flags;
	int version;

	struct timeval pre_delay;
	struct timeval pre_time;
	int new_signal;
};

const int unit = UIRT2_UNIT;
//static int debug = 3;

static ssize_t readagain(int fd, void *buf, size_t count)
{
	ssize_t rc;
	size_t pos=0;
	struct timeval timeout = { .tv_sec = 0, .tv_usec = 200000 };
	fd_set fds;

	rc=read(fd, buf, count);

	if(rc > 0)
	{
		pos+=rc;
	}

	while( (rc == -1 && errno == EAGAIN) || (rc >= 0 && pos < count) )
	{
		FD_ZERO(&fds);
		FD_SET(fd,&fds);

		rc=select(fd + 1, &fds, NULL, NULL, &timeout);

		if(rc == 0)
		{
			/* timeout */
			break;
		}
		else if(rc == -1)
		{
			/* continue for EAGAIN case */
			continue;
		}

		rc=read(fd, ((char *)buf) + pos, count-pos);

		if(rc > 0)
		{
			pos+=rc;
		}

	}
	return (pos == 0) ? -1 : pos;
}

#ifdef DEBUG
static void hexdump(byte_t *buf, int len)
{
	int i;
	char str[200];
	int pos = 0;

	for (i = 0; i < len; i++) {
		if (pos + 3 >= sizeof(str)) {
			break;
		}

		if (!(i % 8)) {
			str[pos++] = ' ';
		}

		sprintf(str + pos, "%02x ", buf[i]);

		pos += 3;
	}

	logprintf(LOG_DEBUG, "%s", str);
}
#endif /* DEBUG */


static int mywaitfordata(uirt2_t *dev, long usec) {
	int fd = dev->fd;
	fd_set fds;
	int maxfd = fd;
	int ret;
	struct timeval tv;

	FD_ZERO(&fds);
	FD_SET(fd,&fds);

	tv.tv_sec = 0;
	tv.tv_usec = usec;

	ret = select(maxfd + 1, &fds, NULL, NULL, &tv);

	if (ret <= 0) {
		return 0;
	} else {
		return 1;
	}
}

static int uirt2_readflush(uirt2_t *dev)
{
	int res;
	char c;

	while(mywaitfordata(dev, (long) 200000) > 0) {
		res = readagain(dev->fd, &c, 1);
		if (res < 1) { 
			return -1;
		}
	}
	return 0;
}


static byte_t checksum(byte_t *data, int len)
{
	int check = 0;
	int i;

	for (i = 0; i < len; i++) {
		check = check - data[i];
	}

	return check & 0xff;
}


static int command_ext(uirt2_t *dev, const byte_t *in, byte_t *out)
{
	byte_t tmp[1024];
	int res;
	int len = in[0];
	const byte_t *buf = in + 1;

	memcpy(tmp, buf, len + 1);

	tmp[len + 1] = checksum(tmp, len + 1) & 0xff;

	if (timerisset(&dev->pre_delay))
	{
		struct timeval cur;
		struct timeval diff;
		struct timeval delay;

		gettimeofday(&cur, NULL);
		timersub(&cur, &dev->pre_time, &diff);
		PRINT_TIME(&diff);

		if(timercmp(&dev->pre_delay, &diff, >))
		{
			timersub(&dev->pre_delay, &diff, &delay);
			PRINT_TIME(&delay);
			
			LOGPRINTF(1, "udelay %lu %lu", 
				  delay.tv_sec, delay.tv_usec);
			sleep(delay.tv_sec);
			usleep(delay.tv_usec);
		}
	
		timerclear(&dev->pre_delay);
	}

	uirt2_readflush(dev);
	
	LOGPRINTF(1, "writing command %02x", buf[0]);

	HEXDUMP(tmp, len + 2);
	res = write(dev->fd, tmp, len + 2);

	if (res < len + 2) {
		logprintf(LOG_ERR, "uirt2_raw: couldn't write command");
		return -1;
	}

	LOGPRINTF(1, "wrote %d", res);

	if (!mywaitfordata(dev, (long) 1000000)) {
		logprintf(LOG_ERR, "uirt2_raw: did not receive results");
		return -1;
	}

	res = readagain(dev->fd, out + 1, out[0]);

	if (res < out[0]) {
		logprintf(LOG_ERR, "uirt2_raw: couldn't read command result");
		return -1;
	}

	LOGPRINTF(1, "cmd res %d:", res);
	HEXDUMP(out + 1, out[0]);
	LOGPRINTF(1, "");

	if (out[0] > 1) {
		int check = checksum(out + 1, out[0]);

		if (check != 0) {
			logprintf(LOG_ERR, "uirt2_raw: checksum error");
			return -1;
		}
	}
    
	return 0;
}


static int command(uirt2_t *dev, const byte_t *buf, int len)
{
	byte_t in[1024];
	byte_t out[2];

	memcpy(in + 1, buf, len+1);
	in[0] = len;
	out[0] = 1;

	if (command_ext(dev, in, out) < 0) {
		return -1;
	}

	return out[1] < UIRT2_CSERROR;
}


static unsigned long calc_bits_length(remstruct1_data_t *buf)
{
	int i;
	byte_t b = 0;
	unsigned long len = 0;
    
	for (i = 0; i < buf->bBits; i++) {
		int bit;

		if (!(i % 8)) {
			b = buf->bDatBits[i / 8];
		}

		bit = b & 1;
		b = b >> 1;

		if (i % 2) {
			// Odd
			if (bit) {
				len += buf->bOff1;
			} else {
				len += buf->bOff0;
			}		
		} else {
			// Even
			if (bit) {
				len += buf->bOn1;
			} else {
				len += buf->bOn0;
			}		
		}
	}

	return unit * len;
}


static unsigned long calc_struct1_length(int repeat, remstruct1_data_t *buf)
{
	int bISDly = unit * (buf->bISDlyLo + 256 * buf->bISDlyHi);
	int bHdr = unit * (buf->bHdr1 + buf->bHdr0);
	unsigned long bBitLength = calc_bits_length(buf);

	LOGPRINTF(1, "bBitLength %lu repeat %d", bBitLength, repeat);

	return (repeat + 1) * (bISDly + bHdr + bBitLength);
}



/*
 * Exported functions 
 */

uirt2_t *uirt2_init(int fd)
{
	uirt2_t *dev = (uirt2_t *)malloc(sizeof(uirt2_t));

	if(dev == NULL)
	{
		logprintf(LOG_ERR, "uirt2_raw: out of memory");
		return NULL;
	}
	
        memset(dev, 0, sizeof(uirt2_t));

	timerclear(&dev->pre_time);
	dev->new_signal = 1;
	dev->flags = UIRT2_MODE_UIR;
	dev->fd = fd;

	uirt2_readflush(dev);

	if(uirt2_getversion(dev, &dev->version) < 0) {
		free(dev);
		return NULL;
	}

	if(dev->version < 0x0104) {
		logprintf(LOG_WARNING, "uirt2_raw: Old UIRT hardware");
	} else {
		logprintf(LOG_INFO, "uirt2_raw: UIRT version %04x ok", 
			  dev->version);
	}

	return dev;
}


int uirt2_uninit(uirt2_t *dev)
{
	free(dev);
	return 0;
}


int uirt2_getmode(uirt2_t *dev)
{
	return (dev->flags & UIRT2_MODE_MASK);
}


int uirt2_setmode(uirt2_t *dev, int mode)
{
	byte_t buf[20];
	byte_t cmd;

	if (uirt2_getmode(dev) == mode)
	{
		LOGPRINTF(1, "uirt2_setmode: already in requested mode");
		return 0;
	}

	switch(mode) {
	case UIRT2_MODE_UIR:
		cmd = UIRT2_SETMODEUIR;
		break;
	case UIRT2_MODE_RAW:
		cmd = UIRT2_SETMODERAW;
		break;
	case UIRT2_MODE_STRUC:
		cmd = UIRT2_SETMODESTRUC;
		break;
	default:
		logprintf(LOG_ERR, "uirt2_raw: bad mode");
		return -1;
	}

	buf[0] = cmd;
	
	if (command(dev, buf, 0) < 0) {
		logprintf(LOG_ERR, "uirt2_raw: setmode failed");
		return -1;
	}

	dev->flags = (dev->flags & ~UIRT2_MODE_MASK) | mode;
	return 0;
}


int uirt2_setmodeuir(uirt2_t *dev)
{
	return uirt2_setmode(dev, UIRT2_MODE_UIR);
}


int uirt2_setmoderaw(uirt2_t *dev)
{
	return uirt2_setmode(dev, UIRT2_MODE_RAW);
}
    

int uirt2_setmodestruc(uirt2_t *dev)
{
	return uirt2_setmode(dev, UIRT2_MODE_STRUC);
}


int uirt2_getversion(uirt2_t *dev, int *version)
{
	byte_t out[20];
	byte_t in[20];

	if(dev->version != 0)
	{
		*version = dev->version;
		return 0;
	}
	
	in[0] = 0;
	in[1] = UIRT2_GETVERSION;
	out[0] = 3;
	
	if (command_ext(dev, in, out) >= 0) {
	        *version = out[2] + (out[1] << 8);
		return 0;
	}

	/* 
	 * Ok, that command didn't work.  Maybe we're 
	 * dealing with a newer version of the UIRT2 
	 * protocol, which sends extended information when 
	 * the version is requested.
	 */
	LOGPRINTF(0, "uirt2: detection of uirt2 failed");
	LOGPRINTF(0, "uirt2: trying to detect newer uirt firmware");
	uirt2_readflush(dev);

	out[0] = 8;
	if (command_ext(dev, in, out) >= 0) {
	       *version = out[2] + (out[1] << 8);
	       return 0;
	}

	return -1;
}


int uirt2_getgpiocaps(uirt2_t *dev, int *slots, byte_t masks[4])
{
	byte_t in[3];
	byte_t out[6];
	
	in[0] = 1;
	in[1] = UIRT2_GETGPIOCAPS;
	in[2] = 1;

	out[0] = 6;

	if (command_ext(dev, in, out) < 0) {
		return -1;
	}

	*slots = out[1];
	memcpy(masks, out + 2, 4);
	return 0;
}


int uirt2_getgpiocfg(uirt2_t *dev, int slot, uirt2_code_t code,
		     int *action, int *duration)
{
	byte_t in[4];
	byte_t out[10];

	in[0] = 2;
	in[1] = UIRT2_GETGPIOCFG;
	in[2] = 2;
	in[3] = slot;
	out[0] = 9;
	
	if(command_ext(dev, in, out) < 0) {
		return -1;
	}

	memcpy(code, out + 1, UIRT2_CODE_SIZE);
	*action = out[UIRT2_CODE_SIZE + 1];
	*duration = out[UIRT2_CODE_SIZE + 2] * 5;
	return 0;
}


int uirt2_setgpiocfg(uirt2_t *dev, int slot, uirt2_code_t code,
		     int action, int duration)
{
	byte_t in[12];

	in[0] = 2;
	in[1] = UIRT2_SETGPIOCFG;
	in[2] = 4 + UIRT2_CODE_SIZE;
	in[3] = slot;
	
	memcpy(in + 4, code, UIRT2_CODE_SIZE);

	in[10] = action;
	in[11] = duration / 5;

	return command(dev, in + 1, in[0]);
}


int uirt2_getgpio(uirt2_t *dev, byte_t ports[4])
{
	byte_t in[3];
	byte_t out[6];

	in[0] = 21;
	in[1] = UIRT2_GETGPIO;
	in[2] = 1;
	out[0] = 5;
	
	if(command_ext(dev, in, out) < 0) {
		return -1;
	}

	memcpy(ports, out + 1, 4);
	return 0;
}


int uirt2_setgpio(uirt2_t *dev, int action, int duration)
{
	byte_t buf[20];

	buf[0] = UIRT2_SETGPIO;
	buf[1] = 3;
	buf[2] = action;
	buf[3] = duration / 5;

	return command(dev, buf, 3);
}


int uirt2_refreshgpio(uirt2_t *dev)
{
	byte_t buf[2];

	buf[0] = UIRT2_REFRESHGPIO;
	buf[1] = 1;

	return command(dev, buf, 1);
}


int uirt2_read_uir(uirt2_t *dev, byte_t *buf, int length)
{
	int pos = 0;
	int res;

	if (uirt2_getmode(dev) != UIRT2_MODE_UIR) {
		logprintf(LOG_ERR, "uirt2_raw: Not in UIR mode");
		return -1;
	}

	while (1) {
		res = readagain(dev->fd, buf + pos, 1);

		if (res == -1) {
			return pos;
		}

		pos += res;

		if (pos == 6) {
			break;
		}
	}
    
	return pos;
}


lirc_t uirt2_read_raw(uirt2_t *dev, lirc_t timeout)
{
	lirc_t data;
	static int pulse = 0;

	if (uirt2_getmode(dev) != UIRT2_MODE_RAW) {
		logprintf(LOG_ERR, "uirt2_raw: Not in RAW mode");
		return -1;
	}

	while (1) {
		int res;
		byte_t b;

		if (!waitfordata(timeout))
			return 0;

		res = readagain(dev->fd, &b, 1);

		if (res == -1) {
			return 0;
		}

		LOGPRINTF(3, "read_raw %02x", b);

		if (b == 0xff) {
			dev->new_signal = 1;
			continue;
		}

		if (dev->new_signal) {
			byte_t isdly[2];

			isdly[0] = b;
			LOGPRINTF(1, "dev->new_signal");

			res = readagain(dev->fd, &isdly[1], 1);

			if (res == -1) {
				return 0;
			}

			data = UIRT2_UNIT * (256 * isdly[0] + isdly[1]);
			pulse = 1;
			dev->new_signal = 0;
		} else {
			data = UIRT2_UNIT * b;
			if (pulse) {
				data = data | PULSE_BIT;
			}
		
			pulse = !pulse;
		}

		return data;
	}

	return 0;
}


int uirt2_send_raw(uirt2_t *dev, byte_t *buf, int length)
{
	byte_t tmp[1024];

	tmp[0] = UIRT2_DOTXRAW;
	tmp[1] = length + 1;
	memcpy(tmp + 2, buf, length);
	
	return command(dev, tmp, length + 1);
}


int uirt2_send_struct1(uirt2_t *dev, int freq, int bRepeatCount,
		       remstruct1_data_t *buf)
{
	int res;
	unsigned long delay;
        remstruct1_t rem;
        remstruct1_ext_t rem_ext;
	
	if(dev->version >= 0x0905)
	{
		byte_t tmp[2+sizeof(remstruct1_ext_t)];
		
		if(freq == 0 || ((5000000 / freq) + 1)/2 >= 0x80)
		{
			rem_ext.bFrequency = 0x80;
	}
		else
		{
			rem_ext.bFrequency = ((5000000 / freq) + 1)/2;
		}
		rem_ext.bRepeatCount = bRepeatCount;
		memcpy(&rem_ext.data, buf, sizeof(*buf));
		
		tmp[0] = 0x37;
		tmp[1] = sizeof(rem_ext) + 1;
		
		memcpy(tmp + 2, &rem_ext, sizeof(rem_ext));
		res = command(dev, tmp, sizeof(rem_ext) + 1);
	}
	else
	{
		if(bRepeatCount > 0x1f)
		{
			rem.bCmd = uirt2_calc_freq(freq) + 0x1f;
		}
		else
		{
			rem.bCmd = uirt2_calc_freq(freq) + bRepeatCount;
		}
		memcpy(&rem.data, buf, sizeof(*buf));
		
		res = command(dev, (byte_t *) &rem, sizeof(rem) - 2);
	}
	delay = calc_struct1_length(bRepeatCount, buf);
	gettimeofday(&dev->pre_time, NULL);
	dev->pre_delay.tv_sec = delay / 1000000;
	dev->pre_delay.tv_usec = delay % 1000000;

	LOGPRINTF(1, "set dev->pre_delay %lu %lu",
		  dev->pre_delay.tv_sec, dev->pre_delay.tv_usec);

	return res;
}


int uirt2_calc_freq(int freq)
{
	if (freq > 39000) {
		return UIRT2_FREQ_40;
	} else if (freq > 37000) {
		return UIRT2_FREQ_38;
	} else {
		return UIRT2_FREQ_36;
	}
}
