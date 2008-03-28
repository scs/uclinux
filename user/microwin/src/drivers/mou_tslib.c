/*
 * tslib mouse driver
 *
 * Copyright (C) 2007
 * Written by Jonathan Kotta <jpkotta@packetdigital.com>
 */

/*           
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "device.h"
extern SCREENDEVICE scrdev;

#include <tslib.h>
static struct tsdev *ts;
static char devnode[64];

#define TSLIB_DEVNODE "/dev/input/event1"

#define TSLIB_PRESSURE_THRESH 100

static int tslib_open(MOUSEDEVICE *pmd)
{	     
    if (getenv("TSLIB_TSDEVICE"))
        strncpy(devnode, getenv("TSLIB_TSDEVICE"), 64);
    else
        strncpy(devnode, TSLIB_DEVNODE, 64);

    ts = ts_open(devnode, 1);

    if (!ts) {
        EPRINTF("Error %d opening tslib device [%s]\n",
                errno, devnode);
        return -1;
    }

    if (ts_config(ts)) {
        EPRINTF("Error %d configuring tslib\n",
                errno);
        return -1;
    }

    /* GdHideCursor(&scrdev); */
    return ts_fd(ts);
}

static void tslib_close(void)
{
    int err;

    if(!ts || ts_fd(ts) < 0)
	return;

    err = ts_close(ts);
    if (err)
	EPRINTF("Error %d closing tslib device [%s]\n", 
		err, devnode);
}

static int tslib_get_button_info(void)
{
	/* get "mouse" buttons supported */
	return MWBUTTON_L;
}

static void tslib_get_default_accel(int *pscale,int *pthresh)
{
	*pscale = 3;
	*pthresh = 5;
}

static int tslib_read(MWCOORD *px, MWCOORD *py, MWCOORD *pz, int *pb, int mode)
{
    struct ts_sample sample;
    int ret;

    ret = ts_read(ts, &sample, 1);
    if (ret < 0) {
	EPRINTF("[%s] Error %d reading from tslib\n", 
		devnode, errno);
	return -1;
    }

    *px = sample.x;
    *py = sample.y;
    *pz = sample.pressure;

    if (sample.pressure > TSLIB_PRESSURE_THRESH)
	*pb = MWBUTTON_L;
    else
	*pb = 0;

    if(!*pb)
	return 3;
    return 2;
}

MOUSEDEVICE mousedev = {
    .Open = tslib_open,
    .Close = tslib_close,
    .GetButtonInfo = tslib_get_button_info,
    .GetDefaultAccel = tslib_get_default_accel,
    .Read = tslib_read,
    .Poll = NULL,
    .flags = MOUSE_TRANSFORM,   /* Input filter flags */
};
