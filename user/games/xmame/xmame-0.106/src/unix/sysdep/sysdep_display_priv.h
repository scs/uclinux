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
#ifndef __SYSDEP_DISPLAY_PRIV_H
#define __SYSDEP_DISPLAY_PRIV_H

#include "mode.h"
#include "sysdep/sysdep_display.h"
#include "begin_code.h"

typedef void (*blit_func_p)(mame_bitmap *bitmap,
  rectangle *vis_in_dest_out, rectangle *dirty_area,
  struct sysdep_palette_struct *palette, unsigned char *dest, int dest_width);

/* from sysdep_display.c */
extern struct sysdep_display_open_params sysdep_display_params;

void sysdep_display_orient_bounds(rectangle *bounds, int width, int height);
void sysdep_display_check_bounds(mame_bitmap *bitmap, rectangle *vis_in_dest_out, rectangle *dirty_area, int x_align);

/* from the sysdep display driver */
int  sysdep_display_driver_open(int reopen);
int  sysdep_display_driver_update_keyboard(void);
void sysdep_display_driver_clear_buffer(void);

/* find out of blitting from sysdep_display_params.depth to
   dest_depth including scaling, rotation and effects will result in
   exactly the same bitmap, in this case the blitting can be skipped under
   certain circumstances. */
int sysdep_display_blit_dest_bitmap_equals_src_bitmap(void);

/* from effect.c
 *
 * called from sysdep_display_open;
 * initializes function pointers to correct depths
 * and allocates buffer for doublebuffering.
 *
 * The caller should call sysdep_display_effect_close() on failure and when
 * done, to free (partly) allocated buffers */
blit_func_p sysdep_display_effect_open(void);
void sysdep_display_effect_close(void);
int sysdep_display_set_up_rotation(void);

#include "end_code.h"
#endif /* ifndef __SYSDEP_DISPLAY_PRIV_H */
