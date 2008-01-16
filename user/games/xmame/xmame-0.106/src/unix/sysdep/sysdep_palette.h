/* Sysdep palette abstraction and emulation object

   Copyright 1999,2000 Hans de Goede
   
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
#ifndef __SYSDEP_PALETTE_H
#define __SYSDEP_PALETTE_H

#include "begin_code.h"

#define FOURCC_YUY2 0x32595559
#define FOURCC_YV12 0x32315659
#define FOURCC_I420 0x30323449
#define FOURCC_UYVY 0x59565955

/* This struct is used to describe the displays palette */
struct sysdep_palette_info
{
   int fourcc_format;   /* 0 for normal RGB, other wise fourcc format code
                           if this is set and the src_depth <= 16 the
                           lookup table will be filled with YUYV values */
   int red_shift;       /* shifts and masks to calculate true_color palette */
   int green_shift;     /* entries , only used when fourcc_format == 0 */
   int blue_shift;
   int red_mask;
   int green_mask;
   int blue_mask;
   int depth;           /* color depth */
   int bpp;             /* bits per pixel */
};

struct sysdep_palette_struct
{
   int src_depth;
   struct sysdep_palette_info *display_palette;
   unsigned int *lookup;  /* lookup table to be used for blitters to convert
                             the src palette to the display palette */
};

/* This function creates a sysdep palette object for the current
   display, which can be used with the display update functions.

   Parameters:
   src_depth       Color "depth" of the src palette valid values:
   		   15 555 direct rgb mode
   		   16 palettised mode
   		   32 888 direct rgb mode 
                   
   Return value:
   A pointer to the sysdep palette object, or NULL on failure.
   Upon failure an error message wil be printed to stderr.
*/
struct sysdep_palette_struct *sysdep_palette_create(struct sysdep_palette_info *display_palette, int src_depth);
   
/* destructor */
void sysdep_palette_destroy(struct sysdep_palette_struct *palette);

/* set a pen for 16 bpp palettised mode */   
void sysdep_palette_set_pen(struct sysdep_palette_struct *palette, int pen,
   unsigned char red, unsigned char green, unsigned char blue);
   
/* for downsampling 32 bits true color modes */   
unsigned int sysdep_palette_make_pen(struct sysdep_palette_struct *palette,
   unsigned int rgb);

#include "end_code.h"
#endif /* ifndef __SYSDEP_PALETTE_H */
