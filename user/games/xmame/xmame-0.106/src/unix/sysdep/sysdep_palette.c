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
/* Changelog
Version 0.1, November 1999
-initial release (Hans de Goede)
*/
#include <stdio.h>
#include <stdlib.h>
#include <driver.h>
#include <math.h>
#include "sysdep_palette.h"
#include "blit/pixel_defs.h"

static unsigned int sysdep_palette_make_pen_from_info(struct sysdep_palette_info
   *info, unsigned char red, unsigned char green, unsigned char blue)
{
   int pen = 0;
   
   /* are the shifts initialised ? */
   if(!info->red_shift)
   {
      for(pen = 1 << (8 * sizeof(pen) - 1); pen && (!(pen & info->red_mask));
         pen >>= 1, info->red_shift++);

      for(pen = 1 << (8 * sizeof(pen) - 1); pen && (!(pen & info->green_mask));
         pen >>= 1, info->green_shift++);

      for(pen = 1 << (8 * sizeof(pen) - 1); pen && (!(pen & info->blue_mask));
         pen >>= 1, info->blue_shift++);
   }
   
   pen  = ((red   << 24) >> info->red_shift)   & info->red_mask;
   pen |= ((green << 24) >> info->green_shift) & info->green_mask;
   pen |= ((blue  << 24) >> info->blue_shift)  & info->blue_mask;
   
   return pen;
}


/* public methods */
struct sysdep_palette_struct *sysdep_palette_create(
  struct sysdep_palette_info *display_palette, int src_depth)
{
   int r,g,b, need_lookup = 0;
   struct sysdep_palette_struct *palette = NULL;
   
   
   /* allocate the palette struct */
   if (!(palette = calloc(1, sizeof(struct sysdep_palette_struct))))
   {
      fprintf(stderr,
         "error malloc failed for struct sysdep_palette_struct\n");
      return NULL;
   }
   
   palette->display_palette = display_palette;
   palette->src_depth       = src_depth;

   /* allocate lookup if needed and verify that we've got a valid src_depth */
   switch (src_depth)
   {
      case 15:
         if ((display_palette->fourcc_format != 0) ||
             (display_palette->red_mask   != (0x1F << 10)) ||
             (display_palette->green_mask != (0x1F <<  5)) ||
             (display_palette->blue_mask  != (0x1F      )))
            need_lookup = 1;
         break;
      case 16:
         need_lookup = 1;
         break;
      case 32:
         if (display_palette->fourcc_format == FOURCC_YUY2)
           need_lookup = 1;
         break;
      default:
      	 fprintf(stderr, "error unknown src_depth: %d\n", src_depth);
         sysdep_palette_destroy(palette);
         return NULL;
   }

   if (need_lookup && !(palette->lookup = calloc(65536, sizeof(unsigned int))))
   {
      fprintf(stderr, "error malloc failed for color lookup table\n");
      sysdep_palette_destroy(palette);
      return NULL;
   }
   
   /* do we need to fill the lookup table? */
   if ((src_depth == 15) && palette->lookup)
   {
   	for (r = 0; r < 32; r++)
   		for (g = 0; g < 32; g++)
   			for (b = 0; b < 32; b++)
   			{
   				int idx = (r << 10) | (g << 5) | b;
   				sysdep_palette_set_pen(palette,
   						idx,
   						(r << 3) | (r >> 2),
   						(g << 3) | (g >> 2),
   						(b << 3) | (b >> 2));
   			}
   }
   else if ((src_depth == 32) && palette->lookup)
   {
   	for (r = 0; r < 32; r++)
   		for (g = 0; g < 64; g++)
   			for (b = 0; b < 32; b++)
   			{
   				int idx = (r << 11) | (g << 5) | b;
   				sysdep_palette_set_pen(palette,
   						idx,
   						(r << 3) | (r >> 2),
   						(g << 2) | (g >> 4),
   						(b << 3) | (b >> 2));
   			}
   }
   
   return palette;
}

/* destructor */
void sysdep_palette_destroy(struct sysdep_palette_struct *palette)
{
   if (palette->lookup)
      free(palette->lookup);
   free(palette);
}

/* set a pen for 16 bpp palettised mode */   
void sysdep_palette_set_pen(struct sysdep_palette_struct *palette, int pen,
   unsigned char red, unsigned char green, unsigned char blue)
{
   if (!palette->lookup)
      return;
      
   /* printf("pen:%4d r:%3d g:%3d b:%3d\n", pen, (int)red, (int)green,
     (int)blue); */
   
   if (palette->display_palette->fourcc_format == 0)
      palette->lookup[pen] = sysdep_palette_make_pen_from_info(
                             palette->display_palette, red, green, blue);
   else
   {
   	int y,u,v;
   	
        RGB2YUV(red,green,blue,y,u,v);

        /* Storing this data in YUYV order simplifies using the data for
           YUY2, both with and without smoothing... */
        palette->lookup[pen]=(y<<Y1SHIFT)|(u<<USHIFT)|(y<<Y2SHIFT)|(v<<VSHIFT);
   }
}

/* for downsampling 32 bits true color modes */   
unsigned int sysdep_palette_make_pen(struct sysdep_palette_struct *palette,
   unsigned int rgb)
{
   return sysdep_palette_make_pen_from_info(palette->display_palette,
      (rgb & 0x00FF0000) >> 16,
      (rgb & 0x0000FF00) >> 8,
      (rgb & 0x000000FF));
}
