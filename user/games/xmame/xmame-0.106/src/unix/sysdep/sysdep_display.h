/* Sysdep display object

   Copyright 2000-2004 Hans de Goede
   
   This file and the acompanying files in this directory are free software;
   you can redistribute them and/or modify them under the terms of the GNU
   Library General Public License as published by the Free Software Foundation;
   either version 2 of the License, or (at your option) any later version.

   These files are distributed in the hope that they will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with these files; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.
*/
#ifndef __SYSDEP_DISPLAY_H
#define __SYSDEP_DISPLAY_H

#include "sysdep/rc.h"
#include "sysdep/sysdep_palette.h"
#include "begin_code.h"

/* 
 * Assume 5 mice even if USE_XINPUT_DEVICES isn't defined, in case there are 
 * multiple lightguns.
 */
#define SYSDEP_DISPLAY_MOUSE_MAX	5
#define SYSDEP_DISPLAY_MOUSE_BUTTONS	8
#define SYSDEP_DISPLAY_MOUSE_AXES	8

/* sysdep_display_update flags */
#define SYSDEP_DISPLAY_HOTKEY_OPTION0   0x0001
#define SYSDEP_DISPLAY_HOTKEY_OPTION1   0x0002
#define SYSDEP_DISPLAY_HOTKEY_OPTION2   0x0004
#define SYSDEP_DISPLAY_HOTKEY_OPTION3   0x0008
#define SYSDEP_DISPLAY_HOTKEY_OPTION4   0x0010
#define SYSDEP_DISPLAY_HOTKEY_GRABMOUSE 0x0040
#define SYSDEP_DISPLAY_HOTKEY_GRABKEYB  0x0080

#define SYSDEP_DISPLAY_UI_DIRTY         0x0100

/* orientation flags */
#define SYSDEP_DISPLAY_FLIPX		0x01
#define SYSDEP_DISPLAY_FLIPY		0x02
#define SYSDEP_DISPLAY_SWAPXY		0x04

/* effect type */
#define SYSDEP_DISPLAY_EFFECT_NONE        0
#define SYSDEP_DISPLAY_EFFECT_SCALE2X     1
#define SYSDEP_DISPLAY_EFFECT_LQ2X        2
#define SYSDEP_DISPLAY_EFFECT_HQ2X        3
#define SYSDEP_DISPLAY_EFFECT_6TAP2X      4
#define SYSDEP_DISPLAY_EFFECT_SCAN2_H     5
#define SYSDEP_DISPLAY_EFFECT_RGBSCAN_H   6
#define SYSDEP_DISPLAY_EFFECT_SCAN3_H     7
#define SYSDEP_DISPLAY_EFFECT_FAKESCAN_H  8
#define SYSDEP_DISPLAY_EFFECT_SCAN2_V     9
#define SYSDEP_DISPLAY_EFFECT_RGBSCAN_V  10
#define SYSDEP_DISPLAY_EFFECT_SCAN3_V    11
#define SYSDEP_DISPLAY_EFFECT_FAKESCAN_V 12

#define SYSDEP_DISPLAY_EFFECT_SCAN_H    SYSDEP_DISPLAY_EFFECT_SCAN2_H
#define SYSDEP_DISPLAY_EFFECT_SCAN_V    SYSDEP_DISPLAY_EFFECT_SCAN2_V
#define SYSDEP_DISPLAY_EFFECT_LAST      SYSDEP_DISPLAY_EFFECT_FAKESCAN_V

/* display properties mode flags */
#define SYSDEP_DISPLAY_WINDOWED		0x01
#define SYSDEP_DISPLAY_FULLSCREEN	0x02
#define SYSDEP_DISPLAY_HWSCALE 		0x04
#define SYSDEP_DISPLAY_EFFECTS		0x08
#define SYSDEP_DISPLAY_DIRECT_FB        0x10
/* number of modes */
#define SYSDEP_DISPLAY_VIDEO_MODES	5

/* effect properties flags */
#define SYSDEP_DISPLAY_X_SCALE_LOCKED        0x01
#define SYSDEP_DISPLAY_Y_SCALE_LOCKED        0x02

/* flags for the return value of sysdep_display_change_params */
#define SYSDEP_DISPLAY_PROPERTIES_CHANGED         0x01
#define SYSDEP_DISPLAY_SCALING_EFFECT_CHANGED     0x02
#define SYSDEP_DISPLAY_VIDMODE_FULLSCREEN_CHANGED 0x04

/* flags for the return value of sysdep_display_update_keyboard */
#define SYSDEP_DISPLAY_KEYBOARD_SYNC_LOST 0x01
#define SYSDEP_DISPLAY_QUIT_REQUESTED     0x02

/* from mame's palette.h */
#ifndef __PALETTE_H__
typedef unsigned int rgb_t;
#endif

/* from mame's vidhrwd/vector.h */
#ifndef __VECTOR__
typedef struct
{
	int x; int y;
	rgb_t col;
	int intensity;
	int arg1; int arg2; /* start/end in pixel array or clipping info */
	int status;         /* for dirty and clipping handling */
	rgb_t (*callback)(void);
} point;
#endif

/* from mame's mamecore.h */
#ifndef __MAMECORE_H__
typedef unsigned int pen_t;

struct _mame_bitmap
{
	int width,height;	/* width and height of the bitmap */
	int depth;			/* bits per pixel */
	void **line;		/* pointers to the start of each line - can be UINT8 **, UINT16 ** or UINT32 ** */

	/* alternate way of accessing the pixels */
	void *base;			/* pointer to pixel (0,0) (adjusted for padding) */
	int rowpixels;		/* pixels per row (including padding) */
	int rowbytes;		/* bytes per row (including padding) */

	/* functions to render in the correct orientation */
	void (*plot)(struct _mame_bitmap *bitmap,int x,int y,pen_t pen);
	pen_t (*read)(struct _mame_bitmap *bitmap,int x,int y);
	void (*plot_box)(struct _mame_bitmap *bitmap,int x,int y,int width,int height,pen_t pen);
};
typedef struct _mame_bitmap mame_bitmap;

struct _rectangle
{
	int min_x,max_x;
	int min_y,max_y;
};
typedef struct _rectangle rectangle;
#endif

struct sysdep_display_mousedata
{
	int buttons[SYSDEP_DISPLAY_MOUSE_BUTTONS];
	int deltas[SYSDEP_DISPLAY_MOUSE_AXES];
};

struct sysdep_display_keyboard_event
{
	unsigned char press;
	unsigned char scancode;
	unsigned short unicode;
};

struct sysdep_display_open_params {
  /* width and height before scaling of the part of bitmap to be displayed */  
  int width;
  int height;
  /* "depth" of the bitmap to be displayed (15/32 direct or 16 palettised) */
  int depth;
  /* should we rotate and or flip ? */
  int orientation;
  /* maximum width and height before scaling of the part of the bitmap to be
     displayed, this is used to determine the size of internal structures
     so that these structures don't have to be recreated when a different
     width and height are set through sysdep_display_change_params().
     width and height may NEVER exceed these values! If you really need
     a bigger display it is allowed to change these values, which will result
     in a recreation of the internal structures. It is strongly encouraged
     to set this to the biggest value you will use on open. */
  int max_width;
  int max_height;
  /* title of the window */
  const char *title;
  /* some sysdep display driver have multiple sub-drivers this selects
     which one to use */
  int video_mode;
  /* scaling and effect options */
  int widthscale;
  int heightscale;
  int yarbsize;
  int effect;
  int fullscreen;
  /* aspect ratio of the bitmap, or 0 if the aspect ratio should not be taken
     into account */
  double aspect_ratio;
  /* keyboard event handler */
  void (*keyboard_handler)(struct sysdep_display_keyboard_event *event);
  /* vectorgame bounds (only used by drivers which have special vector code) */
  const rectangle *vec_src_bounds;
  const rectangle *vec_dest_bounds;
};

struct sysdep_display_properties_struct {
  /* Per mode info availabe after sysdep_display_init. Except for the
     DIRECT_FB flag which is only valid after a successfull open */
  int mode_info[SYSDEP_DISPLAY_VIDEO_MODES];
  const char *mode_name[SYSDEP_DISPLAY_VIDEO_MODES];
  /* info available after sysdep_display_open */
  unsigned int max_width, max_height;
  struct sysdep_palette_info palette_info;
  int (*vector_renderer)(point *pt, int num_points);
};

struct sysdep_display_effect_properties_struct {
  int min_widthscale;
  int max_widthscale;
  int min_heightscale;
  int max_heightscale;
  int flags;
  const char *name;
};

/* init / exit */
int sysdep_display_init(void);
void sysdep_display_exit(void);

/* open / close */
int sysdep_display_open(struct sysdep_display_open_params *params);
void sysdep_display_close(void);

/* change params, this function will always honor the following parts of the
   param struct: width, height, depth, orientation, vec_src_bounds and
   vec_dest_bounds. All other params may be left at their original value if
   the change request can't be met.
   
   This function may change sysdep_display_properties in the case the
   SYSDEP_DISPLAY_PROPERTIES_CHANGED_FLAG is set in the return value.
   
   Under certain circumstances this function may even change the parameters
   not listed above to a different value then their original or new value.
   In this case the following flags will be set in the return value:
   SYSDEP_DISPLAY_SCALING_EFFECT_CHANGED:
     widthscale and heightscale have been set to 1, yarbsize and effect to 0
   SYSDEP_DISPLAY_VIDMODE_FULLSCREEN_CHANGED
     video_mode and fullscreen have been set to 0 */
int sysdep_display_change_params(
  struct sysdep_display_open_params *new_params);

/* update */
const char *sysdep_display_update(mame_bitmap *bitmap,
  rectangle *vis_area, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, int keyb_leds, int flags);

/* input */
int  sysdep_display_update_keyboard(void);
void sysdep_display_update_mouse(void);

/* misc */
/* Check if widthscale, heightscale and yarbsize are compatible with
   the chosen effect, if not update them so that they are. Always returns 0,
   except if params->effect is an invalid value. */
int sysdep_display_check_effect_params(struct sysdep_display_open_params *params);

/* variables */
extern struct sysdep_display_mousedata sysdep_display_mouse_data[SYSDEP_DISPLAY_MOUSE_MAX];
extern struct rc_option sysdep_display_opts[];
extern struct sysdep_display_properties_struct sysdep_display_properties;
extern const struct sysdep_display_effect_properties_struct sysdep_display_effect_properties[];

#include "end_code.h"
#endif /* ifndef __SYSDEP_DISPLAY_H */
