/* normal blitting routines */

#if SRC_DEPTH != DEST_DEPTH || SRC_DEPTH == 16
INLINE void FUNC_NAME(blit_normal_line_1)(SRC_PIXEL *src,
  SRC_PIXEL *end, RENDER_PIXEL *dst, unsigned int *lookup)
{
   for(;src<end;src+=4,dst+=4)
   {
      *(dst  ) = GETPIXEL(*(src  ));
      *(dst+1) = GETPIXEL(*(src+1));
      *(dst+2) = GETPIXEL(*(src+2));
      *(dst+3) = GETPIXEL(*(src+3));
   }
}
#endif

INLINE void FUNC_NAME(blit_normal_line_2)(SRC_PIXEL *src,
  SRC_PIXEL *end, RENDER_PIXEL *dst, unsigned int *lookup)
{
   for(;src<end; src+=4, dst+=8)
   {
      *(dst+ 1) = *(dst   ) = GETPIXEL(*(src  ));
      *(dst+ 3) = *(dst+ 2) = GETPIXEL(*(src+1));
      *(dst+ 5) = *(dst+ 4) = GETPIXEL(*(src+2));
      *(dst+ 7) = *(dst+ 6) = GETPIXEL(*(src+3));
   }
}

INLINE void FUNC_NAME(blit_normal_line_3)(SRC_PIXEL *src,
  SRC_PIXEL *end, RENDER_PIXEL *dst, unsigned int *lookup)
{
   for(;src<end; src+=4, dst+=12)
   {
      *(dst+ 2) = *(dst+ 1) = *(dst   ) = GETPIXEL(*(src  ));
      *(dst+ 5) = *(dst+ 4) = *(dst+ 3) = GETPIXEL(*(src+1));
      *(dst+ 8) = *(dst+ 7) = *(dst+ 6) = GETPIXEL(*(src+2));
      *(dst+11) = *(dst+10) = *(dst+ 9) = GETPIXEL(*(src+3));
   }
}

INLINE void FUNC_NAME(blit_normal_line_x)(SRC_PIXEL *src,
  SRC_PIXEL *end, RENDER_PIXEL *dst, unsigned int *lookup)
{
   for(;src<end;src++)
   {
      const DEST_PIXEL v = GETPIXEL(*(src));
      dst+=sysdep_display_params.widthscale;
      switch (sysdep_display_params.widthscale)
      {
         case 8:      *(dst-8) = v;
         case 7:      *(dst-7) = v;
         case 6:      *(dst-6) = v;
         case 5:      *(dst-5) = v;
         case 4:      *(dst-4) = v;
                      *(dst-3) = v;
                      *(dst-2) = v;
                      *(dst-1) = v;
      }
   }
}

BLIT_BEGIN(blit_normal)
  switch(sysdep_display_params.widthscale)
  {
    case 1:
#if SRC_DEPTH != DEST_DEPTH || SRC_DEPTH == 16
      BLIT_LOOP_YARBSIZE(blit_normal_line_1)
#else /* Speedup hack in case we just have to memcpy */
      if (sysdep_display_params.orientation) {
        if (sysdep_display_properties.mode_info[
             sysdep_display_params.video_mode] &
             SYSDEP_DISPLAY_DIRECT_FB)
        { 
          for (y = dirty_area->min_y; y < dirty_area->max_y; y++) {
            int reps = ((y+1)*yarbsize)/sysdep_display_params.height -
              (y*yarbsize)/sysdep_display_params.height;
            while (reps) {
              rotate_func(line_dest, bitmap, y, dirty_area);
              line_dest += DEST_WIDTH;
              reps--;
            }
          }
        } else {
          for (y = dirty_area->min_y; y < dirty_area->max_y; y++) {
            int reps = ((y+1)*yarbsize)/sysdep_display_params.height -
              (y*yarbsize)/sysdep_display_params.height;
            if (reps) {
              rotate_func(line_dest, bitmap, y, dirty_area);
              while (--reps) {
                memcpy(line_dest+DEST_WIDTH, line_dest,
                  (vis_in_dest_out->max_x-vis_in_dest_out->min_x)*
                  DEST_PIXEL_SIZE);
                line_dest += DEST_WIDTH;
              }
              line_dest += DEST_WIDTH;
            }
          }
        }
      } else {
        for (y = dirty_area->min_y; y < dirty_area->max_y; y++) {
          int reps = ((y+1)*yarbsize)/sysdep_display_params.height -
            (y*yarbsize)/sysdep_display_params.height;
          while (reps) {
            memcpy(line_dest,
              ((SRC_PIXEL *)(bitmap->line[y])) + dirty_area->min_x,
              (vis_in_dest_out->max_x-vis_in_dest_out->min_x)*DEST_PIXEL_SIZE);
            line_dest += DEST_WIDTH;
            reps--;
          }
        }
      }
#endif
      break;
    case 2:
      BLIT_LOOP_YARBSIZE(blit_normal_line_2)
      break;
    case 3:
      BLIT_LOOP_YARBSIZE(blit_normal_line_3)
      break;
    default:
      BLIT_LOOP_YARBSIZE(blit_normal_line_x)
  }
BLIT_END

BLIT_BEGIN(blit_fakescan_h)
  switch(sysdep_display_params.widthscale)
  {
    case 1:
#if SRC_DEPTH != DEST_DEPTH || SRC_DEPTH == 16
      BLIT_LOOP_FAKESCAN(blit_normal_line_1)
#else /* Speedup hack in case we just have to memcpy */
      if (sysdep_display_params.orientation) {
        if (sysdep_display_properties.mode_info[
             sysdep_display_params.video_mode] &
             SYSDEP_DISPLAY_DIRECT_FB)
        { 
          for (y = dirty_area->min_y; y < dirty_area->max_y; y++) {
            int reps = sysdep_display_params.heightscale-1;
            while (reps) {
              rotate_func(line_dest, bitmap, y, dirty_area);
              line_dest += DEST_WIDTH;
              reps--;
            }
            line_dest += DEST_WIDTH;
          }
        } else {
          for (y = dirty_area->min_y; y < dirty_area->max_y; y++) {
            int reps = sysdep_display_params.heightscale-1;
            rotate_func(line_dest, bitmap, y, dirty_area);
            while (--reps) {
              memcpy(line_dest+DEST_WIDTH, line_dest,
                (vis_in_dest_out->max_x-vis_in_dest_out->min_x)*
                DEST_PIXEL_SIZE);
              line_dest += DEST_WIDTH;
            }
            line_dest += 2*DEST_WIDTH;
          }
        }
      } else {
        for (y = dirty_area->min_y; y < dirty_area->max_y; y++) {
          int reps = sysdep_display_params.heightscale-1;
          while(reps) {
            memcpy(line_dest,
              ((SRC_PIXEL *)(bitmap->line[y])) + dirty_area->min_x,
              (vis_in_dest_out->max_x-vis_in_dest_out->min_x)*DEST_PIXEL_SIZE);
            line_dest += DEST_WIDTH;
            reps--;
          }
          line_dest += DEST_WIDTH;
        }
      }
#endif
      break;
    case 2:
      BLIT_LOOP_FAKESCAN(blit_normal_line_2)
      break;
    case 3:
      BLIT_LOOP_FAKESCAN(blit_normal_line_3)
      break;
    default:
      BLIT_LOOP_FAKESCAN(blit_normal_line_x)
  }
BLIT_END
