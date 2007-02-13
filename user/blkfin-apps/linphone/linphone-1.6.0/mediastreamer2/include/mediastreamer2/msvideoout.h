/*
mediastreamer2 library - modular sound and video processing and streaming
Copyright (C) 2006  Simon MORLAT (simon.morlat@linphone.org)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#ifndef msvideoout_h
#define msvideoout_h

#include "msfilter.h"

typedef struct _MSFrameBuffer{
	int w,h;/* set by MSVideoOut */
	uint8_t *y,*u,*v;/* set in return of init() by the MSDisplay*/
} MSFrameBuffer;

struct _MSDisplay;

typedef struct _MSDisplayDesc{
	bool_t (*init)(struct _MSDisplay *, MSFrameBuffer *frame_buffer);
	void (*lock)(struct _MSDisplay *);/*lock before writing to the framebuffer*/
	void (*unlock)(struct _MSDisplay *);/*unlock after writing to the framebuffer*/
	void (*update)(struct _MSDisplay *); /*display the picture to the screen*/
	void (*uninit)(struct _MSDisplay *);
}MSDisplayDesc;

typedef struct _MSDisplay{
	MSDisplayDesc *desc;
	long window_id; /*window id if the display should use an existing window*/
	void *data;
} MSDisplay;


#define ms_display_init(d,fbuf)	(d)->desc->init(d,fbuf)
#define ms_display_lock(d)	if ((d)->desc->lock) (d)->desc->lock(d)
#define ms_display_unlock(d)	if ((d)->desc->unlock) (d)->desc->unlock(d)
#define ms_display_update(d)	if ((d)->desc->update) (d)->desc->update(d)

extern MSDisplayDesc ms_sdl_display_desc;
extern MSDisplayDesc ms_win_display_desc;

#ifdef __cplusplus
extern "C"{
#endif

MSDisplay *ms_display_new(MSDisplayDesc *desc);
void ms_display_set_window_id(MSDisplay *d, long window_id);
void ms_display_destroy(MSDisplay *d);

#define MS_VIDEO_OUT_SET_DISPLAY MS_FILTER_METHOD(MS_VIDEO_OUT_ID,0,MSDisplay*)

#ifdef __cplusplus
}
#endif

#endif
